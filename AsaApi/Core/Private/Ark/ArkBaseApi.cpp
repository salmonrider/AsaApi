#include "ArkBaseApi.h"
#include "..\Private\PDBReader\PDBReader.h"
#include "..\PluginManager\PluginManager.h"
#include "..\Private\Offsets.h"
#include "..\Private\Cache.h"
#include "..\Hooks.h"
#include "..\Commands.h"
#include "Tools.h"
#include <Logger/Logger.h>
#include "HooksImpl.h"
#include "ApiUtils.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "Requests.h"
#include <minizip/unzip.h>
#include <Windows.h>

namespace API
{
	constexpr float api_version = 1.19f;

	ArkBaseApi::ArkBaseApi()
		: commands_(std::make_unique<AsaApi::Commands>()),
		hooks_(std::make_unique<Hooks>()),
		api_utils_(std::make_unique<AsaApi::ApiUtils>())
	{
	}

	bool ArkBaseApi::Init()
	{
		nlohmann::json apiConfig = ArkBaseApi::GetConfig();
		const nlohmann::json autoCacheConfig = apiConfig.value("settings", nlohmann::json::object()).value("AutomaticCacheDownload", nlohmann::json::object());
		namespace fs = std::filesystem;
		
		Log::GetLog()->info("-----------------------------------------------");
		Log::GetLog()->info("ARK:SA Api V{:.2f}", GetVersion());
		Log::GetLog()->info("Brought to you by ArkServerApi");
		Log::GetLog()->info("https://github.com/orgs/ArkServerApi");
		Log::GetLog()->info("Website: https://ark-server-api.com");
		Log::GetLog()->info("Loading...\n");

		PdbReader pdb_reader;

		std::unordered_map<std::string, intptr_t> offsets_dump;
		std::unordered_map<std::string, BitField> bitfields_dump;
		std::unordered_map<std::string, FieldInfo> fields_dump;
		std::unordered_map<std::string, FunctionInfo> functions_dump;

		try
		{
			TCHAR buffer[MAX_PATH];
			GetModuleFileName(NULL, buffer, sizeof(buffer));
			fs::path exe_path = std::filesystem::path(buffer).parent_path();

			const fs::path filepath = fs::path(exe_path).append("ArkAscendedServer.pdb");

			if (!fs::exists(fs::path(exe_path).append(ArkBaseApi::GetApiName())))
				fs::create_directory(fs::path(exe_path).append(ArkBaseApi::GetApiName()));

			if (!fs::exists(fs::path(exe_path).append(ArkBaseApi::GetApiName() + "/Plugins")))
				fs::create_directory(fs::path(exe_path).append(ArkBaseApi::GetApiName() + "/Plugins"));

			if (!fs::exists(fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache")))
				fs::create_directory(fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache"));

			const fs::path pdbIgnoreFile = fs::path(exe_path).append(ArkBaseApi::GetApiName() + "/pdbignores.txt");
			const fs::path keyCacheFile = fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache/cached_key.cache");
			const fs::path offsetsCacheFile = fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache/cached_offsets.cache");
			const fs::path bitfieldsCacheFile = fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache/cached_bitfields.cache");
			const fs::path fieldsCacheFile = fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache/cached_fields.cache");
			const fs::path functionsCacheFile = fs::path(exe_path).append(ArkBaseApi::GetApiName()+"/Cache/cached_functions.cache");
			const fs::path offsetsCacheFilePlain = fs::path(exe_path).append(ArkBaseApi::GetApiName() + "/Cache/cached_offsets.txt");
			const std::string fileHash = Cache::calculateSHA256(filepath);
			std::string storedHash = Cache::readFromFile(keyCacheFile);
			std::unordered_set<std::string> pdbIgnoreSet = Cache::readFileIntoSet(pdbIgnoreFile);

			const fs::path arkApiDir = fs::path(exe_path).append(ArkBaseApi::GetApiName());

			const DWORD dllFlags = LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
				LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
				LOAD_LIBRARY_SEARCH_USER_DIRS;

			if (!SetDefaultDllDirectories(dllFlags))
			{
				const DWORD err = GetLastError();
				Log::GetLog()->warn("SetDefaultDllDirectories failed ({}). Falling back to SetDllDirectoryW.", err);

				std::wstring wApiDir = arkApiDir.wstring();
				if (!SetDllDirectoryW(wApiDir.c_str()))
				{
					Log::GetLog()->warn("SetDllDirectoryW failed ({}) for path: {}", GetLastError(), arkApiDir.string());
				}
			}

			const std::wstring w = arkApiDir.wstring();
			DLL_DIRECTORY_COOKIE cookie = AddDllDirectory(w.c_str());
			if (cookie == nullptr)
			{
				Log::GetLog()->warn("AddDllDirectory failed ({}) for path: {}", GetLastError(), std::filesystem::path(w).string());
			}
			else
			{
				Log::GetLog()->info("Added DLL search directory: {}", std::filesystem::path(w).string());
			}

			if (fileHash != storedHash || !fs::exists(offsetsCacheFile) || !fs::exists(bitfieldsCacheFile))
			{
				Log::GetLog()->info("Cache refresh required this will take few seconds to complete");
				pdb_reader.Read(filepath, &offsets_dump, &bitfields_dump, pdbIgnoreSet, &fields_dump, &functions_dump);

				Log::GetLog()->info("Caching offsets for faster loading next time");
				Cache::serializeMap(offsets_dump, offsetsCacheFile);

				Log::GetLog()->info("Caching bitfields for faster loading next time");
				Cache::serializeMap(bitfields_dump, bitfieldsCacheFile);
				
				Log::GetLog()->info("Caching field type info for faster loading next time");
				Cache::serializeMap(fields_dump, fieldsCacheFile);
				
				Log::GetLog()->info("Caching function info for faster loading next time");
				Cache::serializeMap(functions_dump, functionsCacheFile);
				
				Cache::saveToFile(keyCacheFile, fileHash);
				Cache::saveToFilePlain(offsetsCacheFilePlain, offsets_dump);
			}
			else
			{
				Log::GetLog()->info("Cache is still valid loading existing cache");
				Log::GetLog()->info("Reading cached offsets");
				offsets_dump = Cache::deserializeMap<intptr_t>(offsetsCacheFile);

				Log::GetLog()->info("Reading cached bitfields");
				bitfields_dump = Cache::deserializeMap<BitField>(bitfieldsCacheFile);
				
				if (fs::exists(fieldsCacheFile))
				{
					Log::GetLog()->info("Reading cached field types");
					fields_dump = Cache::deserializeMap<FieldInfo>(fieldsCacheFile);
				}
				
				if (fs::exists(functionsCacheFile))
				{
					Log::GetLog()->info("Reading cached function info");
					functions_dump = Cache::deserializeMap<FunctionInfo>(functionsCacheFile);
				}
			}
		}
		catch (const std::exception& error)
		{
			Log::GetLog()->critical("Failed to read pdb - {}", error.what());
			return false;
		}

		Offsets::Get().Init(move(offsets_dump), move(bitfields_dump), move(fields_dump), move(functions_dump));
		Sleep(10);
		AsaApi::InitHooks();
		Log::GetLog()->info("API was successfully loaded");
		Log::GetLog()->info("-----------------------------------------------\n");

		return true;
	}

	nlohmann::json ArkBaseApi::GetConfig()
	{
		const std::string config_path = AsaApi::Tools::GetCurrentDir() + "/config.json";
		std::ifstream file{ config_path };
		if (!file.is_open())
			return false;

		nlohmann::json config;
		file >> config;
		file.close();

		return config;
	}

	bool ArkBaseApi::DownloadCacheFiles(const std::filesystem::path downloadFile, const std::filesystem::path localFile)
	{
		if (API::Requests::DownloadFile(downloadFile.string(), localFile.string()))
		{
			std::string outputFolder = localFile.parent_path().string();
			unzFile zf = unzOpen(localFile.string().c_str());
			if (zf == nullptr)
				return false;

			unz_global_info globalInfo;
			if (unzGetGlobalInfo(zf, &globalInfo) != UNZ_OK)
			{
				unzClose(zf);
				return false;
			}

			char readBuffer[8192];

			for (uLong i = 0; i < globalInfo.number_entry; ++i)
			{
				unz_file_info fileInfo;
				char filename[256];
				if (unzGetCurrentFileInfo(zf, &fileInfo, filename, sizeof(filename), NULL, 0, NULL, 0) != UNZ_OK)
				{
					unzClose(zf);
					return false;
				}

				const size_t filenameLength = strlen(filename);
				if (filename[filenameLength - 1] == '/')
					continue;
				else
				{
					if (unzOpenCurrentFile(zf) != UNZ_OK)
					{
						unzClose(zf);
						return false;
					}

					std::string fullPath = outputFolder + "/" + filename;
					std::ofstream out(fullPath, std::ios::binary);

					if (!out) 
					{
						unzCloseCurrentFile(zf);
						unzClose(zf);
						return false;
					}

					int bytesRead;
					do {
						bytesRead = unzReadCurrentFile(zf, readBuffer, sizeof(readBuffer));
						if (bytesRead < 0) 
						{
							unzCloseCurrentFile(zf);
							unzClose(zf);
							return false;
						}

						if (bytesRead > 0)
							out.write(readBuffer, bytesRead);
					} while (bytesRead > 0);

					unzCloseCurrentFile(zf);
					out.close();
				}

				if ((i + 1) < globalInfo.number_entry)
				{
					if (unzGoToNextFile(zf) != UNZ_OK)
					{
						unzClose(zf);
						return false;
					}
				}
			}

			unzClose(zf);
		}
		else
			return false;

		Log::GetLog()->info("Cache files downloaded and processed successfully");
		return true;
	}

	float ArkBaseApi::GetVersion()
	{
		return api_version;
	}

	std::string ArkBaseApi::GetApiName()
	{
		return "ArkApi";
	}

	std::unique_ptr<AsaApi::IHooks>& ArkBaseApi::GetHooks()
	{
		return hooks_;
	}

	std::unique_ptr<AsaApi::ICommands>& ArkBaseApi::GetCommands()
	{
		return commands_;
	}

	std::unique_ptr<AsaApi::IApiUtils>& ArkBaseApi::GetApiUtils()
	{
		return api_utils_;
	}

	void ArkBaseApi::RegisterCommands()
	{
		GetCommands()->AddConsoleCommand("plugins.load", &LoadPluginCmd);
		GetCommands()->AddConsoleCommand("plugins.unload", &UnloadPluginCmd);
		GetCommands()->AddConsoleCommand("dumpclass", &DumpClassCmd);
		GetCommands()->AddRconCommand("plugins.load", &LoadPluginRcon);
		GetCommands()->AddRconCommand("plugins.unload", &UnloadPluginRcon);
		GetCommands()->AddRconCommand("map.setserverid", &SetServerID);
		GetCommands()->AddRconCommand("dumpclass", &DumpClassRcon);
	}

	FString ArkBaseApi::LoadPlugin(FString* cmd)
	{
		TArray<FString> parsed;
		cmd->ParseIntoArray(parsed, L" ", true);

		if (parsed.IsValidIndex(1))
		{
			const std::string plugin_name = parsed[1].ToString();

			try
			{
				PluginManager::Get().LoadPlugin(plugin_name);
			}
			catch (const std::exception& error)
			{
				Log::GetLog()->warn("({}) {}", __FUNCTION__, error.what());
				return FString::Format("Failed to load plugin - {}", error.what());
			}

			Log::GetLog()->info("Loaded plugin - {}", plugin_name.c_str());

			return "Successfully loaded plugin";
		}

		return "Plugin not found";
	}

	FString ArkBaseApi::UnloadPlugin(FString* cmd)
	{
		TArray<FString> parsed;
		cmd->ParseIntoArray(parsed, L" ", true);

		if (parsed.IsValidIndex(1))
		{
			const std::string plugin_name = parsed[1].ToString();

			try
			{
				PluginManager::Get().UnloadPlugin(plugin_name);
			}
			catch (const std::exception& error)
			{
				Log::GetLog()->warn("({}) {}", __FUNCTION__, error.what());
				return *FString::Format("Failed to unload plugin - {}", error.what());
			}

			Log::GetLog()->info("Unloaded plugin - {}", plugin_name.c_str());

			return L"Successfully unloaded plugin";
		}

		return L"Plugin not found";
	}

	// Command Callbacks
	void ArkBaseApi::LoadPluginCmd(APlayerController* player_controller, FString* cmd, bool /*unused*/)
	{
		auto* shooter_controller = static_cast<AShooterPlayerController*>(player_controller);
		AsaApi::GetApiUtils().SendServerMessage(shooter_controller, FColorList::Green, *LoadPlugin(cmd));
	}

	void ArkBaseApi::UnloadPluginCmd(APlayerController* player_controller, FString* cmd, bool /*unused*/)
	{
		auto* shooter_controller = static_cast<AShooterPlayerController*>(player_controller);
		AsaApi::GetApiUtils().SendServerMessage(shooter_controller, FColorList::Green, *UnloadPlugin(cmd));
	}

	// RCON Command Callbacks
	void ArkBaseApi::LoadPluginRcon(RCONClientConnection* rcon_connection, RCONPacket* rcon_packet, UWorld* /*unused*/)
	{
		FString reply = LoadPlugin(&rcon_packet->Body);
		rcon_connection->SendMessageW(rcon_packet->Id, 0, &reply);
	}

	void ArkBaseApi::UnloadPluginRcon(RCONClientConnection* rcon_connection, RCONPacket* rcon_packet,
		UWorld* /*unused*/)
	{
		FString reply = UnloadPlugin(&rcon_packet->Body);
		rcon_connection->SendMessageW(rcon_packet->Id, 0, &reply);
	}

	void ArkBaseApi::SetServerID(RCONClientConnection* rcon_connection, RCONPacket* rcon_packet,
		UWorld* /*unused*/)
	{
		FString reply = "Set new server id";
		TArray<FString> parsed;
		rcon_packet->Body.ParseIntoArray(parsed, L" ", true);

		if (parsed.IsValidIndex(1))
		{
			int new_server_id = std::stoi(parsed[1].ToString());

			try
			{
				const auto& actors = AsaApi::GetApiUtils().GetWorld()->PersistentLevelField().Get()->ActorsField();
				for (auto actor : actors)
				{
					FString bp = AsaApi::GetApiUtils().GetBlueprint(actor);
					if (bp.Equals("Blueprint'/Script/ShooterGame.PrimalPersistentWorldData'"))
					{
						actor->TargetingTeamField() = new_server_id;

						AsaApi::GetApiUtils().GetShooterGameMode()->MyServerIdField() = FString(std::to_string(new_server_id));
						AsaApi::GetApiUtils().GetShooterGameMode()->ServerIDField() = new_server_id;
						Log::GetLog()->info("SERVER ID: {}", new_server_id);
						Log::GetLog()->info("Forcing world save to lock-in new server id");
						AsaApi::GetApiUtils().GetShooterGameMode()->SaveWorld(false, true, false);

						break;
					}
				}
			}
			catch (const std::exception& error)
			{
				Log::GetLog()->warn("({}) {}", __FUNCTION__, error.what());
				reply = FString::Format("Failed to set server id - {}", error.what());
			}
		}
		else
			reply = L"You must specify a unique server id.";

		
		rcon_connection->SendMessageW(rcon_packet->Id, 0, &reply);
	}

	FString ArkBaseApi::DumpClass(FString* cmd) {
		TArray<FString> parsed;
		cmd->ParseIntoArray(parsed, L" ", true);

		if (!parsed.IsValidIndex(1)) {
			return L"Usage: dumpclass <ClassName>";
		}

		const std::string className = parsed[1].ToString();
		const bool isGlobal = (className == "Global");
		
		try {
			namespace fs = std::filesystem;
			
			TCHAR buffer[MAX_PATH];
			GetModuleFileName(NULL, buffer, sizeof(buffer));
			fs::path exe_path = fs::path(buffer).parent_path();
			
			const fs::path dumpDir = exe_path / "ArkApi" / "ClassDumps";
			if (!fs::exists(dumpDir))
				fs::create_directories(dumpDir);
			
			const fs::path outputFile = dumpDir / (className + ".h");
			std::ofstream file(outputFile);
			
			if (!file.is_open()) {
				return FString::Format("Failed to create output file: {}", outputFile.string().c_str());
			}
			
			auto fields = Offsets::Get().GetFieldsForClass(className);
			auto bitfields = Offsets::Get().GetBitFieldsForClass(className);
			auto functions = Offsets::Get().GetFunctionsForClass(className);
			
			if (fields.empty() && bitfields.empty() && functions.empty()) {
				file.close();
				fs::remove(outputFile);
				return FString::Format("No data found for class: {}", className.c_str());
			}
			
			std::sort(fields.begin(), fields.end(), [](const auto& a, const auto& b) { return a.second.offset < b.second.offset; });
			std::sort(bitfields.begin(), bitfields.end(), [](const auto& a, const auto& b) { return a.second.offset < b.second.offset; });
			std::sort(functions.begin(), functions.end(), [](const auto& a, const auto& b) { return a.second.signature < b.second.signature; });

			if (isGlobal) {
				file << "namespace " << className << "\n{\n";
			}
			else {
				file << "struct " << className << "\n{\n";
			}
			
			if (!fields.empty()) {
				file << "\t// Fields\n\n";
				for (const auto& [key, info] : fields) {
					size_t dotPos = key.rfind('.');
					std::string memberName = (dotPos != std::string::npos) ? key.substr(dotPos + 1) : key;
					
					if (isGlobal) {
						file << "\tinline " << info.type << "& " << memberName << "Field() { return *GetNativeDataPointerField<" << info.type << "*>(nullptr, \"" << key << "\"); }\n";
					}
					else {
						file << "\t" << info.type << "& " << memberName << "Field() { return *GetNativePointerField<" << info.type << "*>(this, \"" << key << "\"); }\n";
					}
				}
			}
			
			if (!bitfields.empty()) {
				file << "\n\t// Bitfields\n\n";
				for (const auto& [key, bf] : bitfields) {
					size_t dotPos = key.rfind('.');
					std::string memberName = (dotPos != std::string::npos) ? key.substr(dotPos + 1) : key;
					
					if (isGlobal) {
						file << "\tinline BitFieldValue<bool, unsigned __int32> " << memberName << "Field() { return { nullptr, \"" << key << "\" }; }\n";
					}
					else {
						file << "\tBitFieldValue<bool, unsigned __int32> " << memberName << "Field() { return { this, \"" << key << "\" }; }\n";
					}
				}
			}
			
			if (!functions.empty()) {
				file << "\n\t// Functions\n\n";
				for (const auto& [key, info] : functions) {
					if (info.signature.rfind("exec", 0) == 0)
						continue;
					
					std::string paramTypes = info.params;
					std::vector<std::string> paramNamesList;
					if (!info.paramNames.empty()) {
						std::string name;
						for (char c : info.paramNames) {
							if (c == ',') {
								if (!name.empty()) paramNamesList.push_back(name);
								name.clear();
							}
							else {
								name += c;
							}
						}
						if (!name.empty()) paramNamesList.push_back(name);
					}

					std::string paramDecl;
					std::string paramCall;
					if (!info.params.empty()) {
						std::vector<std::string> paramList;
						std::string param;
						int depth = 0;
						for (char c : info.params) {
							if (c == '<') depth++;
							else if (c == '>') depth--;
							else if (c == ',' && depth == 0) {
								paramList.push_back(param);
								param.clear();
								continue;
							}
							param += c;
						}
						if (!param.empty()) paramList.push_back(param);
						
						for (size_t i = 0; i < paramList.size(); i++) {
							if (i > 0) {
								paramDecl += ", ";
								paramCall += ", ";
							}

							std::string paramName = (i < paramNamesList.size()) ? paramNamesList[i] : ("arg" + std::to_string(i));
							paramDecl += paramList[i] + " " + paramName;
							paramCall += paramName;
						}
					}
					
					size_t parenPos = info.signature.find('(');
					std::string funcName = (parenPos != std::string::npos) ? info.signature.substr(0, parenPos) : info.signature;
					
					if (isGlobal) {
						if (info.returnType == "void" || info.returnType.empty()) {
							if (paramTypes.empty())
								file << "\tinline void " << funcName << "() { NativeCall<void>(nullptr, \"" << key << "\"); }\n";
							else
								file << "\tinline void " << funcName << "(" << paramDecl << ") { NativeCall<void, " << paramTypes << ">(nullptr, \"" << key << "\", " << paramCall << "); }\n";
						}
						else {
							if (paramTypes.empty())
								file << "\tinline " << info.returnType << " " << funcName << "() { return NativeCall<" << info.returnType << ">(nullptr, \"" << key << "\"); }\n";
							else
								file << "\tinline " << info.returnType << " " << funcName << "(" << paramDecl << ") { return NativeCall<" << info.returnType << ", " << paramTypes << ">(nullptr, \"" << key << "\", " << paramCall << "); }\n";
						}
					}
					else if (info.isStatic) {
						if (info.returnType == "void" || info.returnType.empty()) {
							if (paramTypes.empty())
								file << "\tstatic void " << funcName << "() { NativeCall<void>(nullptr, \"" << key << "\"); }\n";
							else
								file << "\tstatic void " << funcName << "(" << paramDecl << ") { NativeCall<void, " << paramTypes << ">(nullptr, \"" << key << "\", " << paramCall << "); }\n";
						}
						else {
							if (paramTypes.empty())
								file << "\tstatic " << info.returnType << " " << funcName << "() { return NativeCall<" << info.returnType << ">(nullptr, \"" << key << "\"); }\n";
							else
								file << "\tstatic " << info.returnType << " " << funcName << "(" << paramDecl << ") { return NativeCall<" << info.returnType << ", " << paramTypes << ">(nullptr, \"" << key << "\", " << paramCall << "); }\n";
						}
					}
					else {
						if (info.returnType == "void" || info.returnType.empty()) {
							if (paramTypes.empty())
								file << "\tvoid " << funcName << "() { NativeCall<void>(this, \"" << key << "\"); }\n";
							else
								file << "\tvoid " << funcName << "(" << paramDecl << ") { NativeCall<void, " << paramTypes << ">(this, \"" << key << "\", " << paramCall << "); }\n";
						}
						else {
							if (paramTypes.empty())
								file << "\t" << info.returnType << " " << funcName << "() { return NativeCall<" << info.returnType << ">(this, \"" << key << "\"); }\n";
							else
								file << "\t" << info.returnType << " " << funcName << "(" << paramDecl << ") { return NativeCall<" << info.returnType << ", " << paramTypes << ">(this, \"" << key << "\", " << paramCall << "); }\n";
						}
					}
				}
			}
			
			file << "};\n";
			file.close();
			
			Log::GetLog()->info("Class dump saved to: {}", outputFile.string());
			return FString::Format("Class dump saved to: {}", outputFile.string().c_str());
		}
		catch (const std::exception& error) {
			Log::GetLog()->warn("({}) {}", __FUNCTION__, error.what());
			return FString::Format("Failed to dump class - {}", error.what());
		}
	}

	void ArkBaseApi::DumpClassCmd(APlayerController* player_controller, FString* cmd, bool /*unused*/) {
		auto* shooter_controller = static_cast<AShooterPlayerController*>(player_controller);
		AsaApi::GetApiUtils().SendServerMessage(shooter_controller, FColorList::Green, *DumpClass(cmd));
	}

	void ArkBaseApi::DumpClassRcon(RCONClientConnection* rcon_connection, RCONPacket* rcon_packet, UWorld* /*unused*/) {
		FString reply = DumpClass(&rcon_packet->Body);
		rcon_connection->SendMessageW(rcon_packet->Id, 0, &reply);
	}
} // namespace API
