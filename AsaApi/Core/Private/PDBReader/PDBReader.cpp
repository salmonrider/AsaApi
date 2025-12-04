#include "PDBReader.h"

#include <fstream>
#include <algorithm>
#include <future>
#include <sstream>
#include <cstring>

#include <Logger/Logger.h>
#include <Tools.h>

#include "../Private/Helpers.h"
#include "../Private/Offsets.h"

#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")

// raw_pdb includes
#include "PDB.h"
#include "PDB_RawFile.h"
#include "PDB_InfoStream.h"
#include "PDB_DBIStream.h"
#include "PDB_TPIStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_ModuleSymbolStream.h"
#include "PDB_ImageSectionStream.h"
#include "PDB_GlobalSymbolStream.h"
#include "PDB_PublicSymbolStream.h"
#include "PDB_CoalescedMSFStream.h"
#include "PDB_TPITypes.h"
#include "PDB_DBITypes.h"

namespace API
{
	struct MemoryMappedFile
	{
		void* baseAddress = nullptr;
		size_t length = 0;
		HANDLE fileHandle = INVALID_HANDLE_VALUE;
		HANDLE mappingHandle = nullptr;

		static MemoryMappedFile Open(const std::wstring& path)
		{
			MemoryMappedFile file;
			
			file.fileHandle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, 
			                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

			if (file.fileHandle == INVALID_HANDLE_VALUE)
				return file;

			LARGE_INTEGER fileSize;
			if (!GetFileSizeEx(file.fileHandle, &fileSize)) {
				CloseHandle(file.fileHandle);
				file.fileHandle = INVALID_HANDLE_VALUE;
				return file;
			}

			file.length = static_cast<size_t>(fileSize.QuadPart);
			file.mappingHandle = CreateFileMappingW(file.fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
			if (!file.mappingHandle) {
				CloseHandle(file.fileHandle);
				file.fileHandle = INVALID_HANDLE_VALUE;
				return file;
			}

			file.baseAddress = MapViewOfFile(file.mappingHandle, FILE_MAP_READ, 0, 0, 0);
			if (!file.baseAddress) {
				CloseHandle(file.mappingHandle);
				CloseHandle(file.fileHandle);
				file.fileHandle = INVALID_HANDLE_VALUE;
				file.mappingHandle = nullptr;
			}

			return file;
		}

		static void Close(MemoryMappedFile& file) {
			if (file.baseAddress) {
				UnmapViewOfFile(file.baseAddress);
				file.baseAddress = nullptr;
			}

			if (file.mappingHandle) {
				CloseHandle(file.mappingHandle);
				file.mappingHandle = nullptr;
			}

			if (file.fileHandle != INVALID_HANDLE_VALUE) {
				CloseHandle(file.fileHandle);
				file.fileHandle = INVALID_HANDLE_VALUE;
			}
		}
	};

	class TypeTable {
	public:
		TypeTable(const PDB::TPIStream& tpiStream)
			: m_firstTypeIndex(tpiStream.GetFirstTypeIndex())
			, m_lastTypeIndex(tpiStream.GetLastTypeIndex())
			, m_recordCount(tpiStream.GetTypeRecordCount())
		{
			const PDB::DirectMSFStream& directStream = tpiStream.GetDirectMSFStream();
			m_stream = PDB::CoalescedMSFStream(directStream, directStream.GetSize(), 0);

			m_records.resize(m_recordCount);

			uint32_t typeIndex = 0;
			tpiStream.ForEachTypeRecordHeaderAndOffset([this, &typeIndex](const PDB::CodeView::TPI::RecordHeader& header, size_t offset) {
				const PDB::CodeView::TPI::Record* record = m_stream.GetDataAtOffset<const PDB::CodeView::TPI::Record>(offset);
				m_records[typeIndex] = record;
				++typeIndex;
			});
		}

		const PDB::CodeView::TPI::Record* GetTypeRecord(uint32_t typeIndex) const {
			if (typeIndex < m_firstTypeIndex || typeIndex > m_lastTypeIndex)
				return nullptr;
			
			const size_t index = typeIndex - m_firstTypeIndex;
			if (index >= m_records.size())
				return nullptr;

			return m_records[index];
		}

		uint32_t GetFirstTypeIndex() const { return m_firstTypeIndex; }
		uint32_t GetLastTypeIndex() const { return m_lastTypeIndex; }
		const std::vector<const PDB::CodeView::TPI::Record*>& GetTypeRecords() const { return m_records; }

	private:
		uint32_t m_firstTypeIndex;
		uint32_t m_lastTypeIndex;
		size_t m_recordCount;
		std::vector<const PDB::CodeView::TPI::Record*> m_records;
		PDB::CoalescedMSFStream m_stream;
	};

	void PdbReader::AddOffset(const std::string& key, intptr_t value) {
		std::lock_guard<std::mutex> lock(offsets_mutex_);
		(*offsets_dump_)[key] = value;
	}

	void PdbReader::AddBitField(const std::string& key, const BitField& value) {
		std::lock_guard<std::mutex> lock(bitfields_mutex_);
		(*bitfields_dump_)[key] = value;
	}

	void PdbReader::AddFieldInfo(const std::string& key, const std::string& typeName, intptr_t offset, bool isPointer) {
		if (!fields_dump_) return;
		std::lock_guard<std::mutex> lock(fields_mutex_);
		FieldInfo info;
		info.type = typeName;
		info.offset = offset;
		info.isPointer = isPointer;
		(*fields_dump_)[key] = info;
	}

	void PdbReader::AddFunctionInfo(const std::string& key, const std::string& returnType, const std::string& signature, const std::string& params, const std::string& paramNames, intptr_t offset, bool isStatic) {
		if (!functions_dump_) return;
		std::lock_guard<std::mutex> lock(functions_mutex_);
		FunctionInfo info;
		info.returnType = returnType;
		info.signature = signature;
		info.params = params;
		info.paramNames = paramNames;
		info.offset = offset;
		info.isStatic = isStatic;
		(*functions_dump_)[key] = info;
	}

	bool PdbReader::MarkVisited(uint32_t id) {
		std::lock_guard<std::mutex> lock(visited_mutex_);
		if (visited_.find(id) != visited_.end())
			return false;
		visited_.insert(id);
		return true;
	}

	bool PdbReader::FilterSymbols(const std::string& name) const {
		if (name.empty())
			return true;

		for (const auto& filter : filter_set_) {
			if (name.rfind(filter, 0) == 0 && name.rfind("UE::GC", 0) != 0)
				return true;
		}

		if (name.find('`') != std::string::npos)
			return true;

		return false;
	}

	static std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
		size_t pos = 0;
		while ((pos = str.find(from, pos)) != std::string::npos) {
			str.replace(pos, from.length(), to);
			pos += to.length();
		}
		return str;
	}

	std::string UndecorateName(const char* decoratedName, DWORD flags) {
		if (!decoratedName || decoratedName[0] != '?')
			return decoratedName ? decoratedName : "";

		char undecoratedName[4096];
		if (UnDecorateSymbolName(decoratedName, undecoratedName, sizeof(undecoratedName), flags) == 0)
			return decoratedName;

		return std::string(undecoratedName);
	}

	std::string ExtractFunctionParams(const char* name) {
		if (!name)
			return "";

		std::string result;
		
		if (name[0] == '?') 
			result = UndecorateName(name, 0x20000);
		else 
			result = name;
		
		size_t start = result.find('(');
		size_t end = result.rfind(')');
		
		if (start == std::string::npos || end == std::string::npos || end <= start)
			return "";

		std::string params = result.substr(start + 1, end - start - 1);
		
		params = ReplaceAll(params, "struct ", "");
		params = ReplaceAll(params, "class ", "");
		params = ReplaceAll(params, "enum ", "");
		params = ReplaceAll(params, "const ", "");
		params = ReplaceAll(params, " ", "");
		params = ReplaceAll(params, "__ptr64", "");
		
		if (params == "void")
			params.clear();

		return params;
	}

	std::string ExtractReturnType(const char* name) {
		if (!name)
			return "void";

		std::string result;
		
		if (name[0] == '?') 
			result = UndecorateName(name, 0x0);
		else 
			result = name;

		size_t parenPos = result.find('(');
		if (parenPos == std::string::npos)
			return "void";
		
		size_t funcStart = result.rfind(' ', parenPos);
		if (funcStart == std::string::npos)
			return "void";

		std::string beforeFunc = result.substr(0, funcStart);
		beforeFunc = ReplaceAll(beforeFunc, "__cdecl", "");
		beforeFunc = ReplaceAll(beforeFunc, "__stdcall", "");
		beforeFunc = ReplaceAll(beforeFunc, "__fastcall", "");
		beforeFunc = ReplaceAll(beforeFunc, "__thiscall", "");
		beforeFunc = ReplaceAll(beforeFunc, "__vectorcall", "");
		beforeFunc = ReplaceAll(beforeFunc, "public:", "");
		beforeFunc = ReplaceAll(beforeFunc, "private:", "");
		beforeFunc = ReplaceAll(beforeFunc, "protected:", "");
		beforeFunc = ReplaceAll(beforeFunc, "virtual ", "");
		beforeFunc = ReplaceAll(beforeFunc, "static ", "");
		beforeFunc = ReplaceAll(beforeFunc, "struct ", "");
		beforeFunc = ReplaceAll(beforeFunc, "class ", "");
		beforeFunc = ReplaceAll(beforeFunc, "enum ", "");
		beforeFunc = ReplaceAll(beforeFunc, "__ptr64", "");
		
		size_t start = beforeFunc.find_first_not_of(" \t");
		size_t end = beforeFunc.find_last_not_of(" \t");
		if (start == std::string::npos)
			return "void";
		
		std::string returnType = beforeFunc.substr(start, end - start + 1);
		
		if (returnType.empty() || returnType.find_first_not_of(" \t") == std::string::npos)
			return "void";
		
		returnType = ReplaceAll(returnType, " ", "");
		
		return returnType;
	}

	std::string ExtractFunctionName(const char* name) {
		if (!name)
			return "";
			
		std::string result;
		
		if (name[0] == '?')
			result = UndecorateName(name, 0x1000);
		else {
			result = name;
			size_t parenPos = result.find('(');
			if (parenPos != std::string::npos) {
				result = result.substr(0, parenPos);
			}
		}

		return result;
	}

	void PdbReader::CollectFunctionParamNames(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream) {
		const PDB::ModuleInfoStream moduleInfoStream = dbiStream.CreateModuleInfoStream(rawFile);
		const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();

		for (const PDB::ModuleInfoStream::Module& module : modules) {
			if (!module.HasSymbolStream())
				continue;

			const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(rawFile);
			
			uint32_t currentFuncOffset = 0;
			std::string currentFuncKey;
			std::vector<std::string> currentParams;
			bool inFunction = false;
			bool hasThisPointer = false;

			moduleSymbolStream.ForEachSymbol([&](const PDB::CodeView::DBI::Record* record) {
				switch (record->header.kind) {
					case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32:
					case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32:
					case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID:
					case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID: {
						if (inFunction && currentFuncOffset != 0) {
							std::lock_guard<std::mutex> lock(param_names_mutex_);
							if (!currentParams.empty()) {
								std::string paramNamesStr;
								for (size_t i = 0; i < currentParams.size(); i++)
								{
									if (i > 0) paramNamesStr += ",";
									paramNamesStr += currentParams[i];
								}
								param_names_map_[currentFuncOffset] = paramNamesStr;
							}
						}
						if (inFunction && !currentFuncKey.empty()) {
							std::lock_guard<std::mutex> lock(func_has_this_mutex_);
							func_has_this_map_[currentFuncKey] = hasThisPointer;
						}
					
						currentFuncOffset = record->data.S_GPROC32.offset;
						currentParams.clear();
						inFunction = true;
						hasThisPointer = false;
					
						const char* name = record->data.S_GPROC32.name;
						if (name) {
							std::string funcName = ExtractFunctionName(name);
							if (funcName.find("::") != std::string::npos)
								currentFuncKey = ReplaceAll(funcName, "::", ".");
							else
								currentFuncKey = "Global." + funcName;
						}
						else
							currentFuncKey.clear();

						break;
					}
				
					case PDB::CodeView::DBI::SymbolRecordKind::S_REGREL32: {
						if (inFunction) {
							const char* paramName = record->data.S_REGREL32.name;
							if (paramName && paramName[0] != '\0') {
								std::string nameStr = paramName;

								if (nameStr == "this" || nameStr == "_this")
									hasThisPointer = true;
								else
									currentParams.push_back(paramName);
							}
						}

						break;
					}
				
					case PDB::CodeView::DBI::SymbolRecordKind::S_BPREL32: {
						if (inFunction) {
							const char* paramName = record->data.S_BPRELSYM32.name;
							if (paramName && paramName[0] != '\0') {
								std::string nameStr = paramName;

								if (nameStr == "this" || nameStr == "_this")
								{
									hasThisPointer = true;
								}
								else
								{
									currentParams.push_back(paramName);
								}
							}
						}
						break;
					}
				
					case PDB::CodeView::DBI::SymbolRecordKind::S_END:
					case PDB::CodeView::DBI::SymbolRecordKind::S_PROC_ID_END: {
						if (inFunction && currentFuncOffset != 0) {
							std::lock_guard<std::mutex> lock(param_names_mutex_);
							if (!currentParams.empty()) {
								std::string paramNamesStr;
								for (size_t i = 0; i < currentParams.size(); i++) {
									if (i > 0) paramNamesStr += ",";
									paramNamesStr += currentParams[i];
								}
								param_names_map_[currentFuncOffset] = paramNamesStr;
							}
						}
						if (inFunction && !currentFuncKey.empty()) {
							std::lock_guard<std::mutex> lock(func_has_this_mutex_);
							func_has_this_map_[currentFuncKey] = hasThisPointer;
						}

						inFunction = false;
						currentFuncOffset = 0;
						currentFuncKey.clear();
						currentParams.clear();
						hasThisPointer = false;
						break;
					}
				
					default:
						break;
				}
			});
			
			if (inFunction && currentFuncOffset != 0) {
				std::lock_guard<std::mutex> lock(param_names_mutex_);
				if (!currentParams.empty()) {
					std::string paramNamesStr;
					for (size_t i = 0; i < currentParams.size(); i++) {
						if (i > 0) paramNamesStr += ",";
						paramNamesStr += currentParams[i];
					}
					param_names_map_[currentFuncOffset] = paramNamesStr;
				}
			}

			if (inFunction && !currentFuncKey.empty()) {
				std::lock_guard<std::mutex> lock(func_has_this_mutex_);
				func_has_this_map_[currentFuncKey] = hasThisPointer;
			}
		}
	}

	bool PdbReader::FunctionHasThisPointer(const std::string& funcName) const {
		std::string baseName = funcName;
		size_t parenPos = funcName.find('(');
		if (parenPos != std::string::npos) {
			baseName = funcName.substr(0, parenPos);
		}
		
		auto it = func_has_this_map_.find(baseName);
		if (it != func_has_this_map_.end()) {
			return it->second;
		}

		return true;
	}

	void PdbReader::ProcessModuleFunctions(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream) {
		const PDB::ModuleInfoStream moduleInfoStream = dbiStream.CreateModuleInfoStream(rawFile);
		const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();

		for (const PDB::ModuleInfoStream::Module& module : modules) {
			if (!module.HasSymbolStream())
				continue;

			const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(rawFile);

			moduleSymbolStream.ForEachSymbol([&](const PDB::CodeView::DBI::Record* record) {
				if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32 && record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32 && record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID && record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID) return;

				const char* name = record->data.S_GPROC32.name;
				uint32_t offset = record->data.S_GPROC32.offset;

				if (!name || offset == 0)
					return;

				std::string funcName = ExtractFunctionName(name);

				if (FilterSymbols(funcName))
					return;

				std::string params = ExtractFunctionParams(name);

				std::string fullName;
				if (funcName.find("::") != std::string::npos)
					fullName = ReplaceAll(funcName, "::", ".") + "(" + params + ")";
				else
					fullName = "Global." + funcName + "(" + params + ")";

				{
					std::lock_guard<std::mutex> lock(offsets_mutex_);
					if (offsets_dump_->find(fullName) != offsets_dump_->end())
						return;
				}

				AddOffset(fullName, static_cast<intptr_t>(offset));

				std::string returnType = ExtractReturnType(name);
				std::string signature = funcName.substr(funcName.rfind("::") != std::string::npos ? funcName.rfind("::") + 2 : funcName.rfind('.') != std::string::npos ? funcName.rfind('.') + 1 : 0);
				signature += "(" + params + ")";
				
				std::string paramNames = GetParamNamesForOffset(offset);
				bool isMemberFunction = (funcName.find("::") != std::string::npos);
				bool isStatic = isMemberFunction && !FunctionHasThisPointer(fullName);

				AddFunctionInfo(fullName, returnType, signature, params, paramNames, static_cast<intptr_t>(offset), isStatic);
			});
		}
	}

	std::string PdbReader::GetParamNamesForOffset(uint32_t offset) const {
		auto it = param_names_map_.find(offset);
		if (it != param_names_map_.end())
		{
			return it->second;
		}
		return "";
	}

	static size_t GetLeafSize(PDB::CodeView::TPI::TypeRecordKind kind) {
		if (kind < PDB::CodeView::TPI::TypeRecordKind::LF_NUMERIC)
			return sizeof(uint16_t);

		switch (kind) {
			case PDB::CodeView::TPI::TypeRecordKind::LF_CHAR: 
				return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint8_t);
			case PDB::CodeView::TPI::TypeRecordKind::LF_SHORT:
			case PDB::CodeView::TPI::TypeRecordKind::LF_USHORT: 
				return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint16_t);
			case PDB::CodeView::TPI::TypeRecordKind::LF_LONG:
			case PDB::CodeView::TPI::TypeRecordKind::LF_ULONG: 
				return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint32_t);
			case PDB::CodeView::TPI::TypeRecordKind::LF_QUADWORD:
			case PDB::CodeView::TPI::TypeRecordKind::LF_UQUADWORD: 
				return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint64_t);
			default: 
				return 0;
		}
	}

	static uint64_t GetLeafValue(const char* data, PDB::CodeView::TPI::TypeRecordKind kind)
	{
		if (kind < PDB::CodeView::TPI::TypeRecordKind::LF_NUMERIC)
			return *reinterpret_cast<const uint16_t*>(data);

		const char* valueData = data + sizeof(PDB::CodeView::TPI::TypeRecordKind);

		switch (kind) {
			case PDB::CodeView::TPI::TypeRecordKind::LF_CHAR:
				return static_cast<uint64_t>(*reinterpret_cast<const uint8_t*>(valueData));
			case PDB::CodeView::TPI::TypeRecordKind::LF_SHORT:
				return static_cast<uint64_t>(*reinterpret_cast<const int16_t*>(valueData));
			case PDB::CodeView::TPI::TypeRecordKind::LF_USHORT:
				return static_cast<uint64_t>(*reinterpret_cast<const uint16_t*>(valueData));
			case PDB::CodeView::TPI::TypeRecordKind::LF_LONG:
				return static_cast<uint64_t>(*reinterpret_cast<const int32_t*>(valueData));
			case PDB::CodeView::TPI::TypeRecordKind::LF_ULONG:
				return static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(valueData));
			case PDB::CodeView::TPI::TypeRecordKind::LF_QUADWORD:
				return static_cast<uint64_t>(*reinterpret_cast<const int64_t*>(valueData));
			case PDB::CodeView::TPI::TypeRecordKind::LF_UQUADWORD:
				return *reinterpret_cast<const uint64_t*>(valueData);
			default:
				return 0;
		}
	}

	static const char* GetLeafName(const char* data, PDB::CodeView::TPI::TypeRecordKind kind) { return &data[GetLeafSize(kind)]; }

	std::string PdbReader::GetTypeName(const TypeTable& typeTable, uint32_t typeIndex) const { return GetTypeNameInternal(typeTable, typeIndex, 0); }

	std::string PdbReader::GetTypeNameInternal(const TypeTable& typeTable, uint32_t typeIndex, int depth) const {
		if (depth > 50)
			return "<recursive>";

		if (typeIndex < typeTable.GetFirstTypeIndex()) {
			PDB::CodeView::TPI::TypeIndexKind type = (PDB::CodeView::TPI::TypeIndexKind)(typeIndex);
			switch (type) {
				case PDB::CodeView::TPI::TypeIndexKind::T_VOID: return "void";
				case PDB::CodeView::TPI::TypeIndexKind::T_CHAR: return "char";
				case PDB::CodeView::TPI::TypeIndexKind::T_UCHAR: return "unsigned char";
				case PDB::CodeView::TPI::TypeIndexKind::T_SHORT: return "short";
				case PDB::CodeView::TPI::TypeIndexKind::T_USHORT: return "unsigned short";
				case PDB::CodeView::TPI::TypeIndexKind::T_LONG: return "long";
				case PDB::CodeView::TPI::TypeIndexKind::T_ULONG: return "unsigned long";
				case PDB::CodeView::TPI::TypeIndexKind::T_INT4: return "int";
				case PDB::CodeView::TPI::TypeIndexKind::T_UINT4: return "unsigned int";
				case PDB::CodeView::TPI::TypeIndexKind::T_QUAD: return "__int64";
				case PDB::CodeView::TPI::TypeIndexKind::T_UQUAD: return "unsigned __int64";
				case PDB::CodeView::TPI::TypeIndexKind::T_REAL32: return "float";
				case PDB::CodeView::TPI::TypeIndexKind::T_REAL64: return "double";
				case PDB::CodeView::TPI::TypeIndexKind::T_BOOL08: return "bool";
				case PDB::CodeView::TPI::TypeIndexKind::T_WCHAR: return "wchar_t";
				case PDB::CodeView::TPI::TypeIndexKind::T_32PVOID:
				case PDB::CodeView::TPI::TypeIndexKind::T_64PVOID: return "void*";
				default: return "<builtin>";
			}
		}

		const PDB::CodeView::TPI::Record* record = typeTable.GetTypeRecord(typeIndex);
		if (!record)
			return "<unknown>";

		switch (record->header.kind) {
			case PDB::CodeView::TPI::TypeRecordKind::LF_CLASS:
			case PDB::CodeView::TPI::TypeRecordKind::LF_STRUCTURE:
				return GetLeafName(record->data.LF_CLASS.data, record->data.LF_CLASS.lfEasy.kind);
			case PDB::CodeView::TPI::TypeRecordKind::LF_UNION:
				return GetLeafName(record->data.LF_UNION.data, static_cast<PDB::CodeView::TPI::TypeRecordKind>(0));
			case PDB::CodeView::TPI::TypeRecordKind::LF_ENUM:
				return record->data.LF_ENUM.name;
			case PDB::CodeView::TPI::TypeRecordKind::LF_POINTER:
				return GetTypeNameInternal(typeTable, record->data.LF_POINTER.utype, depth + 1) + "*";
			case PDB::CodeView::TPI::TypeRecordKind::LF_MODIFIER:
				return GetTypeNameInternal(typeTable, record->data.LF_MODIFIER.type, depth + 1);
			case PDB::CodeView::TPI::TypeRecordKind::LF_ARRAY:
				return GetTypeNameInternal(typeTable, record->data.LF_ARRAY.elemtype, depth + 1) + "[]";
			default:
				return "<complex_type>";
		}
	}

	void PdbReader::ProcessFieldList(const PDB::CodeView::TPI::Record* record, const std::string& structName, const TypeTable& typeTable) {
		if (!record || record->header.kind != PDB::CodeView::TPI::TypeRecordKind::LF_FIELDLIST)
			return;

		const uint32_t maxSize = record->header.size - sizeof(uint16_t);
		if (maxSize == 0 || maxSize > 1000000)
			return;

		for (size_t i = 0; i < maxSize;) {
            const uint8_t* rawData = reinterpret_cast<const uint8_t*>(&record->data.LF_FIELD.list) + i;
            if (*rawData >= 0xF0) {
                size_t padBytes = (*rawData & 0x0F); i += (padBytes > 0) ? padBytes : 1;
                continue;
            }

			if (i + sizeof(PDB::CodeView::TPI::TypeRecordKind) > maxSize)
				break;

			const PDB::CodeView::TPI::FieldList* fieldRecord = reinterpret_cast<const PDB::CodeView::TPI::FieldList*>(reinterpret_cast<const uint8_t*>(&record->data.LF_FIELD.list) + i);

			if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_MEMBER) {
				uint64_t offset = GetLeafValue(fieldRecord->data.LF_MEMBER.offset, fieldRecord->data.LF_MEMBER.lfEasy.kind);

				const char* memberName = GetLeafName(fieldRecord->data.LF_MEMBER.offset, fieldRecord->data.LF_MEMBER.lfEasy.kind);
				
				if (!memberName || memberName < reinterpret_cast<const char*>(record) || memberName >= reinterpret_cast<const char*>(record) + record->header.size + sizeof(uint16_t)) {
					i += 8;
					i = (i + 3) & ~3;
					continue;
				}

				size_t nameLen = strnlen(memberName, maxSize - i);
				if (nameLen > 0 && nameLen < 1000) {
					const std::string fullName = structName + "." + memberName;
					
					const PDB::CodeView::TPI::Record* memberType = typeTable.GetTypeRecord(fieldRecord->data.LF_MEMBER.index);
					if (memberType && memberType->header.kind == PDB::CodeView::TPI::TypeRecordKind::LF_BITFIELD) {
						BitField bitField;
						bitField.offset = static_cast<DWORD64>(offset);
						bitField.bit_position = memberType->data.LF_BITFIELD.position;
						bitField.num_bits = memberType->data.LF_BITFIELD.length;
						
						uint32_t underlyingType = memberType->data.LF_BITFIELD.type;
						if (underlyingType < typeTable.GetFirstTypeIndex()) {
							uint32_t sizeIndicator = (underlyingType >> 4) & 0x7;
							switch (sizeIndicator) {
								case 0: bitField.length = 1; break;
								case 1: bitField.length = 2; break;
								case 2: bitField.length = 4; break;
								case 3: bitField.length = 8; break;
								default: bitField.length = 4; break;
							}
						}
						else {
							bitField.length = 4;
						}

						AddBitField(fullName, bitField);
					}
					else {
						std::string typeName = GetTypeName(typeTable, fieldRecord->data.LF_MEMBER.index);
						bool isPointer = typeName.back() == '*';
						
						AddOffset(fullName, static_cast<intptr_t>(offset));
						AddFieldInfo(fullName, typeName, static_cast<intptr_t>(offset), isPointer);
					}
				}

				i += static_cast<size_t>(memberName - reinterpret_cast<const char*>(fieldRecord));
				i += nameLen + 1;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_STMEMBER) {
				const char* memberName = fieldRecord->data.LF_STMEMBER.name;
				if (!memberName) {
					i += 8;
					i = (i + 3) & ~3;
					continue;
				}

				size_t nameLen = strnlen(memberName, maxSize - i);
				i += static_cast<size_t>(memberName - reinterpret_cast<const char*>(fieldRecord));
				i += nameLen + 1;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_BCLASS) {
				size_t leafSize = GetLeafSize(fieldRecord->data.LF_BCLASS.lfEasy.kind);
				i += sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(PDB::CodeView::TPI::MemberAttributes) + sizeof(uint32_t) + leafSize;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_INDEX) {
				const PDB::CodeView::TPI::Record* nextRecord = typeTable.GetTypeRecord(fieldRecord->data.LF_INDEX.type);
				if (nextRecord)
					ProcessFieldList(nextRecord, structName, typeTable);
				
				i += sizeof(PDB::CodeView::TPI::FieldList::Data::LF_INDEX);
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_VFUNCTAB) {
				i += sizeof(PDB::CodeView::TPI::FieldList::Data::LF_VFUNCTAB);
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_ONEMETHOD) {
				auto methodProp = static_cast<PDB::CodeView::TPI::MethodProperty>(fieldRecord->data.LF_ONEMETHOD.attributes.mprop);
				const char* methodName = nullptr;
				
				if (methodProp == PDB::CodeView::TPI::MethodProperty::Intro || methodProp == PDB::CodeView::TPI::MethodProperty::PureIntro)
					methodName = &reinterpret_cast<const char*>(fieldRecord->data.LF_ONEMETHOD.vbaseoff)[sizeof(uint32_t)];
				else
					methodName = &reinterpret_cast<const char*>(fieldRecord->data.LF_ONEMETHOD.vbaseoff)[0];
				
				if (!methodName || methodName < reinterpret_cast<const char*>(record)) {
					i += 8;
					i = (i + 3) & ~3;
					continue;
				}

				size_t nameLen = strnlen(methodName, maxSize - i);
				i += static_cast<size_t>(methodName - reinterpret_cast<const char*>(fieldRecord));
				i += nameLen + 1;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_METHOD) {
				const char* methodName = fieldRecord->data.LF_METHOD.name;
				if (!methodName) {
					i += 8;
					i = (i + 3) & ~3;
					continue;
				}

				size_t nameLen = strnlen(methodName, maxSize - i);
				i += static_cast<size_t>(methodName - reinterpret_cast<const char*>(fieldRecord));
				i += nameLen + 1;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_NESTTYPE) {
				const char* nestName = fieldRecord->data.LF_NESTTYPE.name;
				if (!nestName) {
					i += 8;
					i = (i + 3) & ~3;
					continue;
				}

				size_t nameLen = strnlen(nestName, maxSize - i);
				i += static_cast<size_t>(nestName - reinterpret_cast<const char*>(fieldRecord));
				i += nameLen + 1;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_ENUMERATE) {
				const char* enumName = GetLeafName(fieldRecord->data.LF_ENUMERATE.value, fieldRecord->data.LF_ENUMERATE.lfEasy.kind);
				if (!enumName || enumName < reinterpret_cast<const char*>(record)) {
					i += 8;
					i = (i + 3) & ~3;
					continue;
				}

				size_t nameLen = strnlen(enumName, maxSize - i);
				i += static_cast<size_t>(enumName - reinterpret_cast<const char*>(fieldRecord));
				i += nameLen + 1;
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_VBCLASS || fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_IVBCLASS) {
				const uint8_t* basePtr = reinterpret_cast<const uint8_t*>(fieldRecord);
				const uint8_t* leafPtr = reinterpret_cast<const uint8_t*>(&fieldRecord->data.LF_VBCLASS.vbpOffset);

				auto leaf1Kind = *reinterpret_cast<const PDB::CodeView::TPI::TypeRecordKind*>(leafPtr);
				size_t leaf1Size = GetLeafSize(leaf1Kind);

				const uint8_t* leaf2Ptr = leafPtr + leaf1Size;
				auto leaf2Kind = *reinterpret_cast<const PDB::CodeView::TPI::TypeRecordKind*>(leaf2Ptr);
				size_t leaf2Size = GetLeafSize(leaf2Kind);

				i += static_cast<size_t>(leaf2Ptr + leaf2Size - basePtr);
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_FRIENDCLS) {
				i += sizeof(uint16_t) + sizeof(uint32_t);
				i = (i + 3) & ~3;
			}
			else if (fieldRecord->kind == PDB::CodeView::TPI::TypeRecordKind::LF_VFUNCOFF) {
				i += sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t); 
				i = (i + 3) & ~3;
			}
			else {
				// Unknown field type - skip the minimum amount and hope for the best
				size_t oldI = i;
				i += 4;
				i = (i + 3) & ~3;
				
				if (i <= oldI || i >= maxSize)
					break;
			}
		}
	}

	void PdbReader::ProcessStructOrClass(const PDB::CodeView::TPI::Record* record, const TypeTable& typeTable) {
		if (!record)
			return;

		if (record->header.kind != PDB::CodeView::TPI::TypeRecordKind::LF_CLASS && record->header.kind != PDB::CodeView::TPI::TypeRecordKind::LF_STRUCTURE)
			return;

		if (record->data.LF_CLASS.property.fwdref)
			return;

		const char* structName = GetLeafName(record->data.LF_CLASS.data, record->data.LF_CLASS.lfEasy.kind);
		if (!structName || FilterSymbols(structName))
			return;

		const PDB::CodeView::TPI::Record* fieldRecord = typeTable.GetTypeRecord(record->data.LF_CLASS.field);
		if (fieldRecord)
			ProcessFieldList(fieldRecord, structName, typeTable);
	}

	void PdbReader::ProcessTypes(const PDB::TPIStream& tpiStream, const TypeTable& typeTable) {
		for (const auto* record : typeTable.GetTypeRecords()) {
			if (record->header.kind == PDB::CodeView::TPI::TypeRecordKind::LF_CLASS || record->header.kind == PDB::CodeView::TPI::TypeRecordKind::LF_STRUCTURE) {
				ProcessStructOrClass(record, typeTable);
			}
		}
	}

	std::string PdbReader::GetFunctionParams(uint32_t typeIndex, const TypeTable& typeTable)
	{
		const PDB::CodeView::TPI::Record* record = typeTable.GetTypeRecord(typeIndex);
		if (!record)
			return "";

		return "";
	}

	void PdbReader::ProcessFunctions(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream, const PDB::ImageSectionStream& imageSectionStream) {
		// Use public symbol stream which contains mangled names with full signatures
		const PDB::PublicSymbolStream publicSymbolStream = dbiStream.CreatePublicSymbolStream(rawFile);
		const PDB::CoalescedMSFStream symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawFile);
		const PDB::ArrayView<PDB::HashRecord> hashRecords = publicSymbolStream.GetRecords();

		for (const PDB::HashRecord& hashRecord : hashRecords) {
			const PDB::CodeView::DBI::Record* record = publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
			
			if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32)
				continue;

			if (record->data.S_PUB32.flags != PDB::CodeView::DBI::PublicSymbolFlags::Function)
				continue;

			const char* name = record->data.S_PUB32.name;
			// Use raw offset within section, NOT RVA
			// This matches DIA SDK's get_addressOffset behavior
			uint32_t offset = record->data.S_PUB32.offset;

			if (!name || offset == 0)
				continue;

			std::string funcName = ExtractFunctionName(name);
			
			if (FilterSymbols(funcName))
				continue;

			std::string params = ExtractFunctionParams(name);

			std::string fullName;
			if (funcName.find("::") != std::string::npos)
				fullName = ReplaceAll(funcName, "::", ".") + "(" + params + ")";
			else
				fullName = "Global." + funcName + "(" + params + ")";
			
			AddOffset(fullName, static_cast<intptr_t>(offset));
			
			std::string returnType = ExtractReturnType(name);
			std::string signature = funcName.substr(funcName.rfind("::") != std::string::npos ? funcName.rfind("::") + 2 : funcName.rfind('.') != std::string::npos ? funcName.rfind('.') + 1 : 0);
			signature += "(" + params + ")";
			
			bool isMemberFunction = (funcName.find("::") != std::string::npos);
			bool isStatic = isMemberFunction && !FunctionHasThisPointer(fullName);
			
			std::string paramNames = GetParamNamesForOffset(offset);
			
			AddFunctionInfo(fullName, returnType, signature, params, paramNames, static_cast<intptr_t>(offset), isStatic);
		}
	}

	void PdbReader::ProcessGlobalVariables(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream, const PDB::ImageSectionStream& imageSectionStream, const TypeTable& typeTable) {
		const PDB::GlobalSymbolStream globalSymbolStream = dbiStream.CreateGlobalSymbolStream(rawFile);
		const PDB::CoalescedMSFStream symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawFile);

		const PDB::ArrayView<PDB::HashRecord> hashRecords = globalSymbolStream.GetRecords();

		for (const PDB::HashRecord& hashRecord : hashRecords) {
			const PDB::CodeView::DBI::Record* record = globalSymbolStream.GetRecord(symbolRecordStream, hashRecord);
			
			const char* name = nullptr;
			uint32_t offset = 0;
			uint32_t typeIndex = 0;

			if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32) {
				name = record->data.S_GDATA32.name;
				// Use raw section offset, not RVA like raw_pdb
				offset = record->data.S_GDATA32.offset;
				typeIndex = record->data.S_GDATA32.typeIndex;
			}
			else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32) {
				name = record->data.S_LDATA32.name;
				// Use raw section offset, not RVA like raw_pdb
				offset = record->data.S_LDATA32.offset;
				typeIndex = record->data.S_LDATA32.typeIndex;
			}

			if (name && offset != 0 && !FilterSymbols(name)) {
				std::string globalKey = "Global." + std::string(name);
				AddOffset(globalKey, static_cast<intptr_t>(offset));
				
				// Get type name and add field info
				if (typeIndex != 0) {
					std::string typeName = GetTypeName(typeTable, typeIndex);
					if (!typeName.empty()) {
						bool isPointer = (typeName.back() == '*');
						AddFieldInfo(globalKey, typeName, static_cast<intptr_t>(offset), isPointer);
					}
				}
			}
		}
	}

	void PdbReader::Read(const std::wstring& path, std::unordered_map<std::string, intptr_t>* offsets_dump, std::unordered_map<std::string, BitField>* bitfields_dump, const std::unordered_set<std::string> filter_set, std::unordered_map<std::string, FieldInfo>* fields_dump, std::unordered_map<std::string, FunctionInfo>* functions_dump) {
		offsets_dump_ = offsets_dump;
		bitfields_dump_ = bitfields_dump;
		fields_dump_ = fields_dump;
		functions_dump_ = functions_dump;
		filter_set_ = filter_set;

		offsets_dump_->reserve(550000);
		bitfields_dump_->reserve(11000);
		if (fields_dump_) fields_dump_->reserve(300000);
		if (functions_dump_) functions_dump_->reserve(250000);

		std::ifstream f{path};
		if (!f.good())
			throw std::runtime_error("Failed to open pdb file");
		f.close();

		MemoryMappedFile pdbFile = MemoryMappedFile::Open(path);
		if (!pdbFile.baseAddress) {
			Log::GetLog()->error("Cannot memory-map PDB file");
			throw std::runtime_error("Cannot memory-map PDB file");
		}

		PDB::ErrorCode errorCode = PDB::ValidateFile(pdbFile.baseAddress, pdbFile.length);
		if (errorCode != PDB::ErrorCode::Success) {
			MemoryMappedFile::Close(pdbFile);
			Log::GetLog()->error("Invalid PDB file");
			throw std::runtime_error("Invalid PDB file");
		}

		const PDB::RawFile rawPdbFile = PDB::CreateRawFile(pdbFile.baseAddress);

		errorCode = PDB::HasValidDBIStream(rawPdbFile);
		if (errorCode != PDB::ErrorCode::Success) {
			MemoryMappedFile::Close(pdbFile);
			Log::GetLog()->error("Invalid DBI stream");
			throw std::runtime_error("Invalid DBI stream");
		}

		const PDB::InfoStream infoStream(rawPdbFile);
		if (infoStream.UsesDebugFastLink()) {
			MemoryMappedFile::Close(pdbFile);
			Log::GetLog()->error("PDB was linked using unsupported option /DEBUG:FASTLINK");
			throw std::runtime_error("PDB uses /DEBUG:FASTLINK");
		}

		const PDB::DBIStream dbiStream = PDB::CreateDBIStream(rawPdbFile);
		
		errorCode = PDB::HasValidTPIStream(rawPdbFile);
		if (errorCode != PDB::ErrorCode::Success) {
			MemoryMappedFile::Close(pdbFile);
			Log::GetLog()->error("Invalid TPI stream");
			throw std::runtime_error("Invalid TPI stream");
		}

		const PDB::TPIStream tpiStream = PDB::CreateTPIStream(rawPdbFile);
		const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(rawPdbFile);

		Log::GetLog()->info("Creating type table...");
		const TypeTable typeTable(tpiStream);

		Log::GetLog()->info("Collecting function parameter names...");
		CollectFunctionParamNames(rawPdbFile, dbiStream); // Do not put in task, must execute first

		Log::GetLog()->info("Processing structures...");
		auto typesTask = std::async(std::launch::async, [this, &tpiStream, &typeTable]() {
			ProcessTypes(tpiStream, typeTable);
		});

		Log::GetLog()->info("Processing functions...");
		auto functionsTask = std::async(std::launch::async, [this, &rawPdbFile, &dbiStream, &imageSectionStream]() {
			ProcessFunctions(rawPdbFile, dbiStream, imageSectionStream);
		});

		Log::GetLog()->info("Processing global variables...");
		auto globalsTask = std::async(std::launch::async, [this, &rawPdbFile, &dbiStream, &imageSectionStream, &typeTable]() {
			ProcessGlobalVariables(rawPdbFile, dbiStream, imageSectionStream, typeTable);
		});

		// Wait for all tasks to complete
		typesTask.wait();
		functionsTask.wait();
		globalsTask.wait();

		// Cleanup
		MemoryMappedFile::Close(pdbFile);

		Log::GetLog()->info("Successfully read information from PDB\n");
	}
} // namespace API
