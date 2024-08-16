#pragma once

#include <string>
#include <vector>
// causes link errors:
// #include <httplib.h>
#include <string>

constexpr char* VIRUSTOTAL_URL = "http://www.virustotal.com";
constexpr char* VIRUSTOTAL_FILE_URL = "/api/v3/files/";
constexpr char* VIRUSTOTAL_ANALYSES_URL = "/api/v3/analyses/";

struct ScanResult {
	bool success;
	std::string message;
};

class VirusTotal final {

  public:
	// Constructors
	explicit VirusTotal(const char* apiKey);

	ScanResult scan(const std::wstring& filepath);

  private:
	const char* apiKey;
	ScanResult getFromHash(const std::string& filepath);
	ScanResult VirusTotal::uploadAndScan(const std::string& filepath);
	ScanResult checkAnalysisStatus(const std::string& analysisId);
	static void fileToBuffer(std::vector<char>& container, const std::wstring& filePath);
};
