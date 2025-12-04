#pragma once
#include <API/Base.h>
#include "Logger/Logger.h"
#include "PDBReader/PDBReader.h"

#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <iostream>
#include <fstream>

namespace Cache
{
	std::string calculateSHA256(const std::filesystem::path& filename);

	void saveToFile(const std::filesystem::path& filename, const std::string& content);

	std::string readFromFile(const std::filesystem::path& filename);

	// Helper to write a string to binary file
	inline void writeString(std::ofstream& file, const std::string& str)
	{
		std::size_t len = str.size();
		file.write(reinterpret_cast<const char*>(&len), sizeof(len));
		file.write(str.data(), len);
	}

	// Helper to read a string from binary file
	inline bool readString(std::ifstream& file, std::string& str)
	{
		std::size_t len;
		if (!file.read(reinterpret_cast<char*>(&len), sizeof(len)))
			return false;
		str.resize(len);
		return file.read(&str[0], len).good() || file.eof();
	}

	template <typename T>
	void serializeMap(const std::unordered_map<std::string, T>& data, const std::filesystem::path& filename)
	{
		std::ofstream file(filename, std::ios::binary | std::ios::trunc);
		if (!file.is_open())
		{
			Log::GetLog()->error("Error opening file for writing: " + filename.string());
			return;
		}

		for (const auto& entry : data)
		{
			std::size_t keySize = entry.first.size();
			file.write(reinterpret_cast<char*>(&keySize), sizeof(keySize));
			file.write(entry.first.data(), keySize);
			file.write(reinterpret_cast<const char*>(&entry.second), sizeof(T));
		}

		file.close();
	}

	// Specialized serialization for FieldInfo
	template <>
	inline void serializeMap<API::FieldInfo>(const std::unordered_map<std::string, API::FieldInfo>& data, const std::filesystem::path& filename)
	{
		std::ofstream file(filename, std::ios::binary | std::ios::trunc);
		if (!file.is_open())
		{
			Log::GetLog()->error("Error opening file for writing: " + filename.string());
			return;
		}

		for (const auto& entry : data)
		{
			writeString(file, entry.first);
			writeString(file, entry.second.type);
			file.write(reinterpret_cast<const char*>(&entry.second.offset), sizeof(entry.second.offset));
			file.write(reinterpret_cast<const char*>(&entry.second.isPointer), sizeof(entry.second.isPointer));
		}

		file.close();
	}

	// Specialized serialization for FunctionInfo
	template <>
	inline void serializeMap<API::FunctionInfo>(const std::unordered_map<std::string, API::FunctionInfo>& data, const std::filesystem::path& filename)
	{
		std::ofstream file(filename, std::ios::binary | std::ios::trunc);
		if (!file.is_open())
		{
			Log::GetLog()->error("Error opening file for writing: " + filename.string());
			return;
		}

		for (const auto& entry : data)
		{
			writeString(file, entry.first);
			writeString(file, entry.second.returnType);
			writeString(file, entry.second.signature);
			writeString(file, entry.second.params);
			writeString(file, entry.second.paramNames);
			file.write(reinterpret_cast<const char*>(&entry.second.offset), sizeof(entry.second.offset));
			file.write(reinterpret_cast<const char*>(&entry.second.isStatic), sizeof(entry.second.isStatic));
		}

		file.close();
	}

	template <typename T>
	std::unordered_map<std::string, T> deserializeMap(const std::filesystem::path& filename)
	{
		std::unordered_map<std::string, T> data;
		data.reserve(std::filesystem::file_size(filename) / sizeof(T));

		if (!std::filesystem::exists(filename))
		{
			Log::GetLog()->error("File does not exist: " + filename.string());
			return data;
		}

		std::ifstream file(filename, std::ios::binary);
		if (!file.is_open()) {
			Log::GetLog()->error("Error opening file for writing: " + filename.string());
			return data;
		}

		while (file) {
			std::size_t keySize;
			if (file.read(reinterpret_cast<char*>(&keySize), sizeof(keySize))) {
				std::string key;
				key.resize(keySize);
				if (file.read(&key[0], keySize)) {
					T value;
					if (file.read(reinterpret_cast<char*>(&value), sizeof(T))) {
						data[key] = value;
					}
					else {
						Log::GetLog()->error("Error reading value");
					}
				}
				else {
					Log::GetLog()->error("Error reading key");
				}
			}
		}

		file.close();
		return data;
	}

	// Specialized deserialization for FieldInfo
	template <>
	inline std::unordered_map<std::string, API::FieldInfo> deserializeMap<API::FieldInfo>(const std::filesystem::path& filename)
	{
		std::unordered_map<std::string, API::FieldInfo> data;

		if (!std::filesystem::exists(filename))
		{
			Log::GetLog()->error("File does not exist: " + filename.string());
			return data;
		}

		std::ifstream file(filename, std::ios::binary);
		if (!file.is_open())
		{
			Log::GetLog()->error("Error opening file for reading: " + filename.string());
			return data;
		}

		data.reserve(300000);

		std::string key;
		while (readString(file, key))
		{
			API::FieldInfo info;
			if (!readString(file, info.type)) break;
			if (!file.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset))) break;
			if (!file.read(reinterpret_cast<char*>(&info.isPointer), sizeof(info.isPointer))) break;
			data[key] = info;
			key.clear();
		}

		file.close();
		return data;
	}

	// Specialized deserialization for FunctionInfo
	template <>
	inline std::unordered_map<std::string, API::FunctionInfo> deserializeMap<API::FunctionInfo>(const std::filesystem::path& filename)
	{
		std::unordered_map<std::string, API::FunctionInfo> data;

		if (!std::filesystem::exists(filename))
		{
			Log::GetLog()->error("File does not exist: " + filename.string());
			return data;
		}

		std::ifstream file(filename, std::ios::binary);
		if (!file.is_open())
		{
			Log::GetLog()->error("Error opening file for reading: " + filename.string());
			return data;
		}

		data.reserve(250000);

		std::string key;
		while (readString(file, key))
		{
			API::FunctionInfo info;
			if (!readString(file, info.returnType)) break;
			if (!readString(file, info.signature)) break;
			if (!readString(file, info.params)) break;
			if (!readString(file, info.paramNames)) break;
			if (!file.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset))) break;
			if (!file.read(reinterpret_cast<char*>(&info.isStatic), sizeof(info.isStatic))) break;
			data[key] = info;
			key.clear();
		}

		file.close();
		return data;
	}

	void saveToFilePlain(const std::filesystem::path& filename, const std::unordered_map<std::string, intptr_t>& map);

	std::unordered_set<std::string> readFileIntoSet(const std::filesystem::path& filename);

	static const std::unordered_set<std::string> default_filters = {
		"$",
		"<",
		"Z_",
		"z_",
		"zlib",
		"xatlas",
		"_",
		"TSet",
		"TSQVisitor",
		"TReversePredicate",
		"TResourceArray",
		"TResizableCircularQueue",
		"TRenderThreadStruct",
		"TRenderResourcePool",
		"TRenderAssetUpdate",
		"TRemove",
		"TRHILambdaCommand",
		"TRDGLambdaPass",
		"TQueue",
		"TProperty",
		"TPrivateObjectPtr",
		"TPairInitializer",
		"TObjectPtr",
		"TMapBase",
		"TBase",
		"TArray",
		"SharedPointerInternals",
		"TSharedRef",
		"TSizedInlineAllocator",
		"TSparseArray",
		"TTypedElementList",
		"TUniquePtr",
		"TWeakPtr",
		"UE.",
		"UScriptStruct",
		"oo2::",
		"std::",
		"ogg",
		"oidn",
		"ngx",
		"curl",
		"dt",
		"cpp",
		"Vulkan",
		"USynth",
		"UUI",
		"TType",
		"UE.",
		"UE:",
		"TkDOP",
		"TStatic",
		"TSlateBaseNamedArgs",
		"TSharedFromThis",
		"TShaderRefBase",
		"TMeshProcessorShaders",
		"TMaterialCHS",
		"TGraphTask",
		"TDelegate",
		"TCommon",
		"STableRow",
		"SNotification",
		"Nanite",
		"Metasound",
		"IPCGAttributeAccessorT",
		"ITyped",
		"FWide",
		"FView",
		"FSource",
		"FShader",
		"FRig",
		"FRender",
		"FRecast",
		"FRDG",
		"FPixel",
		"FOpen",
		"FOnlineFriendsSpec",
		"FNiagara",
		"FNDI",
		"FMovie",
		"FLumen",
		"FD3D",
		"FComputeShaderUtils",
		"FCombine",
		"Eigen",
		"D3D",
		"Chaos",
		"Build",
		"BINK",
		"Aws",
		"Audio",
		"Add",
		"Algo",
		"PCG",
		"TInd",
		"TSha",
		"TSlate",
		"TWeakBase",
		"UWi",
		"TIndTSha",
		"TSlate",
		"TWeakBase",
		"UWin"
	};
}