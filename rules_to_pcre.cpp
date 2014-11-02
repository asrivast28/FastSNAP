#include "parser_options.hpp"

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <sstream>

#include <pcrecpp.h>

#include <boost/bimap.hpp>


// These are the keywords which are not supported. Rules which contain these are skipped.
static std::string unsupportedKeywords[] = {"byte_test", "byte_jump", "byte_extract"};
// This is the array of all the keywords which require separation of corresponding patterns as they are to be matched at different locations
// in the payload.
static std::string separatorKeywords[] = {"http_client_body", "http_cookie", "http_raw_cookie", "http_header", "http_raw_header", "http_method",
                                          "http_uri", "http_raw_uri", "http_stat_code", "http_stat_msg", "pkt_data", "file_data"};
// This is the array of raw versions of all the keywords defined in the above array.
// Some have existing keywords while some don't.
static std::string rawSeparatorKeywords[] = {"", "http_raw_cookie", "http_raw_cookie", "http_raw_header", "http_raw_header", "",
                                             "http_raw_uri", "http_raw_uri", "", "", "", ""};
// The following array is of same length as the keywords array above and each character corresponds to a Snort specific pcre modifier.
// '\0' is used in places where no appropriate modifier exists.
static char separatorModifiers[] = {'P', 'C', 'K', 'H', 'D', 'M',
                                    'U', 'I', 'S', 'Y', '\0', '\0'};

/**
 * This function returns a vector of unsupported keywords.
 */
std::vector<std::string>
getUnsupportedKeywords ()
{
  size_t unsupportedSize = sizeof(unsupportedKeywords) / sizeof(std::string);

  return std::vector<std::string>(unsupportedKeywords, unsupportedKeywords + unsupportedSize);
}

std::map<std::string, std::string>
getRawKeywordsMap ()
{
  size_t kwSize = sizeof(rawSeparatorKeywords) / sizeof(std::string);

  std::map<std::string, std::string> rm;
  for (size_t i = 0; i < kwSize; ++i) {
    if (!rawSeparatorKeywords[i].empty()) {
      rm.insert(std::make_pair(rawSeparatorKeywords[i], separatorKeywords[i]));
    }
  }
  return rm;
}

/**
 * This function returns a bi-directional map from all the separatorKeywords to their
 * corresponding indices. This could have returned a vector but returning a bi-directional
 * map is, arguably, more convenient. Later on, that is.
 */
boost::bimap<std::string, size_t>
getSeparatorKeywordIndices ()
{
  size_t kwSize = sizeof(separatorKeywords) / sizeof(std::string);
  std::map<std::string, std::string> rkw(getRawKeywordsMap());

  boost::bimap<std::string, size_t> bm;
  size_t index = 1;
  for (size_t i = 0; i < kwSize; ++i) {
    if (rkw.find(separatorKeywords[i]) == rkw.end()) {
      bm.insert(boost::bimap<std::string, size_t>::value_type(separatorKeywords[i], index++));
    }
  }

  return bm; 
}

/**
 * Indices of Snort specific modifiers in final separated pattern list.
 * This is required for pcre mentioned in rules. 0 is for complete payload.
 */
std::map<char, size_t>
getSeparatorModifierIndices ()
{
  static size_t modSize = sizeof(separatorModifiers) / sizeof(char);

  static std::map<char, size_t> sm;
  for (size_t i = 0; i < modSize; ++i) {
    if (separatorModifiers[i] != '\0') {
      sm.insert(std::make_pair(separatorModifiers[i], i + 1));
    }
  }
  return sm;
}

/**
 * This function reads all the uncommented rules from given rules
 * files and returns options for the rules.
 */
std::vector<std::string>
parseRulesFiles (const std::vector<std::string>& rulesFiles)
{
  std::vector<std::string> allOptions;
  pcrecpp::RE optionPattern("\\((.*(?:content:|pcre:).*)\\)");

  std::vector<std::string> unsupportedKeywords(getUnsupportedKeywords());
  std::string unsupportedString = "(";
  for (std::vector<std::string>::const_iterator uk = unsupportedKeywords.begin(); uk != unsupportedKeywords.end(); ++uk) {
    unsupportedString += (*uk + "|");
  }
  *(unsupportedString.rbegin()) = ')';
  pcrecpp::RE unsupportedPattern(unsupportedString);

  for (std::vector<std::string>::const_iterator rf = rulesFiles.begin(); rf != rulesFiles.end(); ++rf) {
    std::ifstream rfstream((*rf).c_str());
    for (std::string rule; std::getline(rfstream, rule); ) {
      std::string newOption;
      if ((rule[0] != '#') && optionPattern.PartialMatch(rule, &newOption)) {
        //std::cout << newOption << std::endl;
        std::string keyword;
        if (unsupportedPattern.PartialMatch(newOption, &keyword)) {
          std::cerr << std::endl;
          std::cerr << "Keyword \"" << keyword << "\" is not supported. Skipping following rule." << std::endl;
          std::cerr << rule << std::endl << std::endl;
        }
        else {
          allOptions.push_back(newOption);
        }
      }
    }
  }
  return allOptions;
}

/**
 * This function returns a pattern for a given vector of pattern specifiers.
 * The pattern specifiers can be a combination of 'content's and 'pcre's.
 */
std::string
getContentPattern (const std::vector<std::string>& patternVector)
{
  pcrecpp::RE contentPattern("content:(!?)\"(.*)\"");
  pcrecpp::RE contentParamPattern("(offset|depth|distance|within):(\\d+)");
  pcrecpp::RE pcrePattern("pcre:(!?)\"\\/(.*)[\\/]?(\\w*)\"", pcrecpp::RE_Options(PCRE_UNGREEDY));
  pcrecpp::RE escapePattern("(\\.|\\^|\\$|\\*|\\+|\\?|\\(|\\)|\\[|\\{|\\\\|\\/)");
  pcrecpp::RE pipePattern("(.*)\\|((?:[A-F\\d]{2} ?)*)\\|");
  pcrecpp::RE hexPattern("([\\dA-F]{2}) ?");

  std::vector<std::string> independentPatterns;
  for (std::vector<std::string>::const_iterator pattern = patternVector.begin(); pattern != patternVector.end(); ++pattern) {
    std::string negation, thisPattern, thisModifiers;

    bool relativePattern = false;

    size_t escapePatternCount = 0;
    size_t hexPatternCount = 0;

    pcrecpp::StringPiece pString(*pattern);
    if ((*pattern).compare(0, 7, "content") == 0) {
      std::string contentString;
      size_t offset = 0, depth = std::string::npos;
      if (contentPattern.Consume(&pString, &negation, &contentString)) {
        escapePatternCount = escapePattern.GlobalReplace("\\\\\\1", &contentString);
        if (pString.as_string().find("nocase;") != std::string::npos) {
          thisModifiers = "i";
        }

        pcrecpp::StringPiece contentSP(contentString.c_str());
        std::string prefix, isRaw;
        while (pipePattern.FindAndConsume(&contentSP, &prefix, &isRaw)) {
          hexPatternCount += hexPattern.GlobalReplace("\\\\x\\1", &isRaw);
          prefix += (isRaw + contentSP.as_string());
          contentSP.set(prefix.c_str());
        }
        contentString = contentSP.as_string();

        std::string param;
        int value;
        while (contentParamPattern.FindAndConsume(&pString, &param, &value)) {
          if (value < 0) {
            throw std::runtime_error("Handling of negative parameter values is not implemented!");
          }

          if (param == "offset") {
            offset = value;
          }
          else if (param == "depth") {
            depth = value;
          }
          else if (param == "distance") {
            offset = value;
            relativePattern = true;
          }
          else { // param == "within"
            depth = value;
            relativePattern = true;
          }
        }
      }
      else {
        throw std::runtime_error("Provided content pattern didn't match the standard pattern!");
      }
      std::stringstream ps;
      if (!thisModifiers.empty()) {
        ps << "(?" << thisModifiers << ":";
      }
      if ((offset > 0) || (depth < std::string::npos)) {
        size_t contentSize = contentString.length() - (escapePatternCount * 1) - (hexPatternCount * 3);
        if (depth < contentSize) {
          throw std::runtime_error("Encountered depth/within less than content string length!");
        }
        if (!relativePattern) {
          ps << "^";
        }
        size_t end = (depth != std::string::npos) ? (offset + depth) - contentSize : 0;
        if ((offset > 0) || (end > offset)) {
          ps << ".{" << offset;
          if (end > offset) {
            ps << "," << end;
          }
          ps << "}";
        }
        if (depth == std::string::npos) {
          ps << ".*";
        }
      }
      else if (relativePattern) {
        ps << ".*";
      }
      ps << contentString;
      if (!thisModifiers.empty()) {
        ps << ")";
      }
      thisPattern = ps.str();
    }
    else { // a pcre pattern
      if (pcrePattern.Consume(&pString, &negation, &thisPattern, &thisModifiers)) {
        size_t index = thisModifiers.find('R');
        if (index != std::string::npos) {
          thisModifiers.replace(index, 1, "");
          relativePattern = true;
        }
        if (!thisModifiers.empty()) {
          thisPattern = "(?" + thisModifiers + ":" + thisPattern + ")";
        }
      }
      else {
        throw std::runtime_error("Provided pcre pattern didn't match the standard pattern!");
      }
    }
    if (!negation.empty()) {
      thisPattern = "(?!" + thisPattern + ")";
    }
    if (relativePattern && (independentPatterns.size() > 0)) {
      (*(independentPatterns.rbegin())).append(thisPattern);
    }
    else {
      independentPatterns.push_back(thisPattern);
    }
  }

  std::string patternString;
  size_t numPatterns = independentPatterns.size();
  if (numPatterns > 1) {
    for (size_t p = 0; p < (numPatterns - 1); ++p) {
      patternString += "(?=.*" + independentPatterns[p] + ")";
    }
    patternString += ".*";
  }
  patternString += independentPatterns[numPatterns - 1];

  return patternString;
}

/**
 * Main function.
 */
int
main (int argc, char** argv)
{
  ParserOptions po;
  try {
    po.parse(argc, argv);
  }
  catch (po::error& pe) {
    std::cerr << pe.what();
    return 1;
  }
  std::vector<std::string> allOptions = parseRulesFiles(po.rulesFiles());

  pcrecpp::RE sidPattern("sid:(\\d+);");
  pcrecpp::RE contentPattern("((content|pcre):.*)(content:|pcre:|$)", pcrecpp::RE_Options(PCRE_UNGREEDY)); 

  size_t kwSize = sizeof(separatorKeywords) / sizeof(std::string);
  std::string separatorString = "(";
  for (size_t i = 0; i < kwSize; ++i) {
    separatorString += (separatorKeywords[i] + "|");
  }
  *(separatorString.rbegin()) = ')';
  pcrecpp::RE keywordPattern(separatorString);

  std::map<char, size_t> separatorModifiers(getSeparatorModifierIndices());
  separatorString = "(";
  for (std::map<char, size_t>::const_iterator sm = separatorModifiers.begin(); sm != separatorModifiers.end(); ++sm) {
    separatorString += (std::string(1, sm->first) + "|");
  }
  *(separatorString.rbegin()) = ')';
  separatorString = "(pcre:\"\\/.*\\/\\w*)" + separatorString + "(\\w*\")";
  pcrecpp::RE pcrePattern(separatorString);

  std::map<std::string, std::ofstream*> fileMap;
  for (std::vector<std::string>::const_iterator option = allOptions.begin(); option != allOptions.end(); ++option) {
    size_t sid;
    if (!sidPattern.PartialMatch(*option, &sid)) {
      throw std::runtime_error("Encountered a rule with no SID!");
    }
    pcrecpp::StringPiece optionString(*option);
    std::map<std::string, std::string> rawKeywordsMap(getRawKeywordsMap());
    boost::bimap<std::string, size_t> separatorKeywordIndices(getSeparatorKeywordIndices());
    std::string thisContent, type, nextContent;
    std::map<std::pair<size_t, bool>, std::vector<std::string> > contentVectors;
    while (!optionString.empty() && contentPattern.FindAndConsume(&optionString, &thisContent, &type, &nextContent)) {
      size_t index = 0;
      if (type == "content") {
        std::string keyword;
        bool isRaw = false;
        if (keywordPattern.PartialMatch(thisContent, &keyword)) {
          std::map<std::string, std::string>::const_iterator rk = rawKeywordsMap.find(keyword);
          if (rk != rawKeywordsMap.end()) {
            keyword = rk->second;
            isRaw = true;
          }
          index = (separatorKeywordIndices.left.find(keyword))->second;
        }
        if ((*option).find("rawbytes;") != std::string::npos) {
          isRaw = true;
        }
        contentVectors[std::make_pair(index, isRaw)].push_back(thisContent);
      }
      else { // type == "pcre"
        pcrecpp::StringPiece contentString(thisContent);
        std::string pcreString, modifier, suffix;
        if (pcrePattern.Consume(&contentString, &pcreString, &modifier, &suffix)) {
          // Modifier was found in the string
          // Set the index as per the modifier and remove the modifier
          index = (separatorModifiers.find(modifier[0]))->second;
          pcreString += suffix;
          pcreString += contentString.as_string();
        }
        else {
          pcreString = thisContent; 
        }
        contentVectors[std::make_pair(index, false)].push_back(pcreString);
      }
      nextContent += optionString.as_string();
      optionString.set(nextContent.c_str());
    }

    for (std::map<std::pair<size_t, bool>, std::vector<std::string> >::const_iterator content = contentVectors.begin(); content != contentVectors.end(); ++content) {
      try {
        std::string patternString = getContentPattern(content->second);

        std::string outputFile = "payload";
        if ((content->first).first > 0) {
          outputFile = (separatorKeywordIndices.right.find((content->first).first))->second;
        }
        if ((content->first).second) {
          outputFile += "_raw";
        }

        std::ostream* out = 0;
        if (po.writeFiles()) {
          if (fileMap.find(outputFile) == fileMap.end()) {
            std::string fileName = outputFile + ".pcort";
            fileMap[outputFile] = new std::ofstream(fileName.c_str(), std::ofstream::out);
          }
          out = fileMap[outputFile];
        }
        else {
          out = &std::cout;
        }
        *(out) << sid << ": " << patternString << std::endl;
      }
      catch (std::runtime_error& e) {
        std::cerr << std::endl;
        std::cerr << "Getting pattern for rule with SID " << sid << " failed." << std::endl;
        std::cerr << e.what() << std::endl << std::endl;
      }
    }
  }
  for (std::map<std::string, std::ofstream*>::iterator f = fileMap.begin(); f != fileMap.end(); ++f) {
    delete f->second;
    f->second = 0;
  }
  return 0;
}
