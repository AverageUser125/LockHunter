
#include <httplib.h>
#include "VirusTotal.h"
#include <sha1.hpp> // Ensure you have the correct path to the SHA1 header
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

VirusTotal::VirusTotal(const char* _apiKey) : apiKey(_apiKey) {
}

ScanResult VirusTotal::scan(const std::wstring& filepath) {
	// Convert std::wstring to std::string (assuming filePath is UTF-8 encoded)
	std::string filePathStr;
	std::transform(filepath.begin(), filepath.end(), std::back_inserter(filePathStr),
				   [](wchar_t c) { return (char)c; });

	// Check if the file exists
	const std::ifstream file(filepath);
	if (!file) {
		return {false, "File not found: " + filePathStr};
	}

	// hash stuff
	ScanResult result = getFromHash(filePathStr);
	if (result.success) {
		try {
			json parsedData = json::parse(result.message);
			json& scanResults = parsedData["data"]["attributes"]["last_analysis_stats"];
			int totalSuspicous =
				static_cast<int>(scanResults["malicious"]) + static_cast<int>(scanResults["suspicious"]);
			int totalValid = totalSuspicous + static_cast<int>(scanResults["harmless"]) +
							 static_cast<int>(scanResults["undetected"]);
			return {true, std::to_string(totalSuspicous) + "/" + std::to_string(totalValid)};
		} catch (json::exception& e) {
			return {false, e.what()};
		}
	}

	result = uploadAndScan(filePathStr);
	if (!result.success)
		return result;

	return checkAnalysisStatus(result.message);
}

ScanResult VirusTotal::getFromHash(const std::string& filepath) {
	// Compute the SHA1 checksum of the file
	std::string sha1_hash;
	try {
		sha1_hash = SHA1::from_file(filepath);
	} catch (const std::exception& e) {
		return {false, "Error computing SHA1 hash: " + std::string(e.what())};
	}

	// Prepare the VirusTotal API URL
	const std::string url = VIRUSTOTAL_FILE_URL + sha1_hash;

	// Set up the HTTP client for VirusTotal
	httplib::Client cli(VIRUSTOTAL_URL);

	// Set up headers with your API key
	std::cout << apiKey << std::endl;
	const httplib::Headers headers = {{"x-apikey", apiKey}, {"accept", "application/json"}};

	// Perform the GET request
	auto res = cli.Get(url, headers);

	if (!res) {
		return {false, "Failed to perform HTTP request."};
	}

	if (res->status != httplib::OK_200) {
		return {false, "HTTP request failed with status: " + std::to_string(res->status)};
	}

	// Return success and the response body
	return {true, res->body};
}

ScanResult VirusTotal::uploadAndScan(const std::string& filepath) {
	std::vector<char> fileBuffer;
	fileToBuffer(fileBuffer, std::wstring(filepath.begin(), filepath.end()));
	// assert(fileBuffer.size() > 260000);
	httplib::Client cli(VIRUSTOTAL_URL);

	httplib::MultipartFormDataItems items = {
		{"file", std::string(fileBuffer.begin(), fileBuffer.end()), "application/octet-stream", "filename"}};

	const httplib::Headers headers = {{"x-apikey", apiKey}};

	auto res = cli.Post(VIRUSTOTAL_FILE_URL, headers, items);

	if (!res) {
		return {false, "Failed to perform HTTP request."};
	}

	if (res->status != httplib::OK_200) {
		return {false, "HTTP request failed with status: " + std::to_string(res->status)};
	}
	try {
		json parsedData = json::parse(res->body);
		const std::string analysisId = parsedData["data"]["id"];

		// Check the analysis status using the analysis ID
		return {true, analysisId};
	} catch (json::exception& e) {
		return {false, e.what()};
	}
}

ScanResult VirusTotal::checkAnalysisStatus(const std::string& analysisId) {
	// Prepare the VirusTotal API URL
	const std::string url = VIRUSTOTAL_ANALYSES_URL + analysisId;

	// Set up the HTTP client for VirusTotal
	httplib::Client cli(VIRUSTOTAL_URL);

	// Set up headers with your API key
	const httplib::Headers headers = {{"x-apikey", apiKey}, {"accept", "application/json"}};

	// Perform the GET request to check analysis status
	auto res = cli.Get(url, headers);

	if (!res) {
		return {false, "Failed to perform HTTP request."};
	}

	if (res->status != httplib::OK_200) {
		return {false, "HTTP request failed with status: " + std::to_string(res->status)};
	}

	try {
		json parsedData = json::parse(res->body);
		std::string status = parsedData["data"]["attributes"]["status"];

		if (status != "completed") {
			return {false, "Analysis not completed yet. Status: " + status};
		}
		json& scanResults = parsedData["data"]["attributes"]["stats"];
		int totalSuspicious = static_cast<int>(scanResults["malicious"]) + static_cast<int>(scanResults["suspicious"]);
		int totalValid =
			totalSuspicious + static_cast<int>(scanResults["harmless"]) + static_cast<int>(scanResults["undetected"]);
		return {true, std::to_string(totalSuspicious) + "/" + std::to_string(totalValid)};

	} catch (json::exception& e) {
		return {false, e.what()};
	}
}

void VirusTotal::fileToBuffer(std::vector<char>& container, const std::wstring& filePath) {
	std::ifstream file(filePath, std::ios::binary);
	std::copy(std::istream_iterator<char>(file), std::istream_iterator<char>(), std::back_inserter(container));
}