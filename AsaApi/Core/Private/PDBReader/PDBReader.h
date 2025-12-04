#pragma once

#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <thread>

#include "json.hpp"
#include <API/Fields.h>

// Forward declarations for raw_pdb
namespace PDB 
{
	class RawFile;
	class TPIStream;
	class DBIStream;
	class ModuleInfoStream;
	class ImageSectionStream;

	namespace CodeView 
	{
		namespace TPI 
		{
			struct Record;
			enum class TypeRecordKind : uint16_t;
		}
		namespace DBI 
		{
			struct Record;
		}
	}
}

namespace API
{
	// Structure to hold field type information
	struct FieldInfo
	{
		std::string type;      // The type name (e.g., "FString", "TArray<int>")
		intptr_t offset;       // Offset within the class
		bool isPointer;        // Whether the type is a pointer
	};

	// Structure to hold function signature information  
	struct FunctionInfo
	{
		std::string returnType;    // Return type
		std::string signature;     // Full signature with params (e.g., "FuncName(int,float)")
		std::string params;        // Just the parameter types (comma-separated)
		std::string paramNames;    // Just the parameter names (comma-separated, e.g., "_this,ForPC,bForced")
		intptr_t offset;           // Function offset
		bool isStatic;             // Whether function is static
	};

	class TypeTable;

	class PdbReader
	{
	public:
		PdbReader() = default;
		~PdbReader() = default;

		void Read(const std::wstring& path, std::unordered_map<std::string, intptr_t>* offsets_dump,
		          std::unordered_map<std::string, BitField>* bitfields_dump, 
		          const std::unordered_set<std::string> filter_set,
		          std::unordered_map<std::string, FieldInfo>* fields_dump = nullptr,
		          std::unordered_map<std::string, FunctionInfo>* functions_dump = nullptr);

	private:
		// Main processing methods
		void ProcessTypes(const PDB::TPIStream& tpiStream, const TypeTable& typeTable);
		void ProcessFunctions(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream, const PDB::ImageSectionStream& imageSectionStream);
		void ProcessGlobalVariables(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream, const PDB::ImageSectionStream& imageSectionStream, const TypeTable& typeTable);

		// Type processing helpers
		void ProcessStructOrClass(const PDB::CodeView::TPI::Record* record, const TypeTable& typeTable);
		void ProcessFieldList(const PDB::CodeView::TPI::Record* record, const std::string& structName, const TypeTable& typeTable);

		std::string GetFunctionParams(uint32_t typeIndex, const TypeTable& typeTable);

		// Utility methods
		bool FilterSymbols(const std::string& name) const;
		std::string GetTypeName(const TypeTable& typeTable, uint32_t typeIndex) const;
		std::string GetTypeNameInternal(const TypeTable& typeTable, uint32_t typeIndex, int depth) const;

		// Thread-safe data access
		void AddOffset(const std::string& key, intptr_t value);
		void AddBitField(const std::string& key, const BitField& value);
		void AddFieldInfo(const std::string& key, const std::string& typeName, intptr_t offset, bool isPointer);
		void AddFunctionInfo(const std::string& key, const std::string& returnType, const std::string& signature, const std::string& params, const std::string& paramNames, intptr_t offset, bool isStatic);
		bool MarkVisited(uint32_t id);
		
		// Parameter names extraction and module function processing
		void CollectFunctionParamNames(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream);
		void ProcessModuleFunctions(const PDB::RawFile& rawFile, const PDB::DBIStream& dbiStream);
		std::string GetParamNamesForOffset(uint32_t offset) const;
		bool FunctionHasThisPointer(const std::string& funcName) const;

		// Data members
		std::unordered_map<std::string, intptr_t>* offsets_dump_{nullptr};
		std::unordered_map<std::string, BitField>* bitfields_dump_{nullptr};
		std::unordered_map<std::string, FieldInfo>* fields_dump_{nullptr};
		std::unordered_map<std::string, FunctionInfo>* functions_dump_{nullptr};
		std::unordered_set<std::string> filter_set_;
		
		// Map from function offset to comma-separated parameter names
		std::unordered_map<uint32_t, std::string> param_names_map_;
		// Map from function name key to whether it has 'this' pointer (non-static member function)
		std::unordered_map<std::string, bool> func_has_this_map_;
		std::mutex param_names_mutex_;
		std::mutex func_has_this_mutex_;

		// Thread synchronization
		std::mutex offsets_mutex_;
		std::mutex bitfields_mutex_;
		std::mutex fields_mutex_;
		std::mutex functions_mutex_;
		std::mutex visited_mutex_;
		std::unordered_set<uint32_t> visited_;
	};
} // namespace API
