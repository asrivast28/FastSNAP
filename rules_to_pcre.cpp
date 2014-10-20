#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <sstream>

#include <pcrecpp.h>

#include <boost/bimap.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;

// These are the keywords which are not supported. Rules which contain these are skipped.
static std::string unsupportedKeywords[] = {"byte_test", "byte_jump", "byte_extract"};
// This is the array of all the keywords which require separation of corresponding patterns as they are to be matched at different locations
// in the payload.
static std::string separatorKeywords[] = {"http_client_body", "http_cookie", "http_raw_cookie", "http_header", "http_raw_header", "http_method",
                                          "http_uri", "http_raw_uri", "http_stat_code", "http_stat_msg", "pkt_data", "file_data"};
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
  static size_t unsupportedSize = sizeof(unsupportedKeywords) / sizeof(std::string);

  return std::vector<std::string>(unsupportedKeywords, unsupportedKeywords + unsupportedSize);
}

/**
 * This function returns a bi-directional map from all the separatorKeywords to their
 * corresponding indices. This could have returned a vector but returning a bi-directional
 * map is, arguably, more convenient. Later on, that is.
 */
boost::bimap<std::string, size_t>
getSeparatorKeywordIndices ()
{
  static size_t kwSize = sizeof(separatorKeywords) / sizeof(std::string);

  static boost::bimap<std::string, size_t> bm;
  for (size_t i = 0; i < kwSize; ++i) {
    bm.insert(boost::bimap<std::string, size_t>::value_type(separatorKeywords[i], i+1));
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
      sm.insert(std::make_pair(separatorModifiers[i], i+1));
    }
  }
  return sm;
}

/**
 * This function parses command line arguments and returns a
 * list of rules files to be parsed.
 */
std::vector<std::string>
parseCommandLineOptions (int argc, char** argv)
{
  std::vector<std::string> rulesFiles;
  po::options_description desc("Snort rules file parser options");
  desc.add_options()
    ("help,h", "Print this message.")
    ("file,f", po::value<std::vector<std::string> >(&rulesFiles), "Snort rules file(s) to be parsed.")
    ("directory,d", po::value<std::string>(), "Directory containing *.rules files.")
    ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);    
  
  if ((argc == 1) || (vm.count("help") > 0)) {
    std::cerr << desc << std::endl;
    throw po::error("");
  }
  if ((vm.count("file") > 0) && (vm.count("directory") > 0)) {
    std::cerr << "Files and directory can't be specified in combination." << std::endl;
    std::cerr << "Please use only one of the options." << std::endl;
    std::cerr << desc << std::endl;
    throw po::error("");
  }
  else if (vm.count("directory") == 1) {
    std::string directory = vm["directory"].as<std::string>();
    if (fs::exists(directory)) {
      for (fs::directory_iterator it(directory); it != fs::directory_iterator(); ++it) {
        if (it->path().extension().string() == ".rules") {
          rulesFiles.push_back(it->path().string());
        }
      }
    }
  }
  return rulesFiles;
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
  pcrecpp::RE pcrePattern("pcre:\"\\/(.*)[\\/]?(\\w*)\"", pcrecpp::RE_Options(PCRE_UNGREEDY));
  pcrecpp::RE escapePattern("(\\.|\\^|\\$|\\*|\\+|\\?|\\(|\\)|\\[|\\{|\\\\)");
  pcrecpp::RE pipePattern("(.*)\\|((?:[A-F\\d]{2} ?)*)\\|");
  pcrecpp::RE hexPattern("([\\dA-F]{2}) ?");

  std::string patternString = "^";
  std::vector<std::string> independentPatterns;
  for (std::vector<std::string>::const_iterator pattern = patternVector.begin(); pattern != patternVector.end(); ++pattern) {
    std::string thisPattern, thisModifiers;

    bool relativePattern = false;
    bool negativePattern = false;

    pcrecpp::StringPiece pString(*pattern);
    if ((*pattern).compare(0, 7, "content") == 0) {
      std::string negation, contentString;
      int offset = 0, depth = 0;
      if (contentPattern.Consume(&pString, &negation, &contentString)) {
        escapePattern.GlobalReplace("\\\\\\1", &contentString);
        if (pString.as_string().find("nocase;") != std::string::npos) {
          thisModifiers = "i";
        }
        if (!negation.empty()) {
          negativePattern = true;
        }

        pcrecpp::StringPiece contentSP(contentString.c_str());
        std::string prefix, rawContent;
        while (pipePattern.FindAndConsume(&contentSP, &prefix, &rawContent)) {
          hexPattern.GlobalReplace("\\\\x\\1", &rawContent);
          prefix += (rawContent + contentSP.as_string());
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
      if ((offset > 0) || (depth > 0)) {
        int end = (offset + depth) - contentString.length();
        if (end != offset) {
          ps << ".{" << offset << "," << end << "}";
        }
      }
      else {
        ps << ".*";
      }
      ps << contentString;
      if (!thisModifiers.empty()) {
        ps << ")";
      }
      thisPattern = ps.str();
      if (negativePattern) {
        thisPattern = "(?!" + thisPattern + ")";
      }
    }
    else { // a pcre pattern
      if (pcrePattern.Consume(&pString, &thisPattern, &thisModifiers)) {
        size_t index = thisModifiers.find('R');
        if (index != std::string::npos) {
          thisModifiers.replace(index, 1, "");
          relativePattern = true;
        }
        if (!thisModifiers.empty()) {
          thisPattern = "(?" + thisModifiers + ":" + thisPattern + ")";
        }
        if (!relativePattern) {
          thisPattern = ".*" + thisPattern;
        }
      }
      else {
        throw std::runtime_error("Provided pcre pattern didn't match the standard pattern!");
      }
    }
    //std::cout << thisPattern << std::endl;
    if (relativePattern && (independentPatterns.size() > 0)) {
      (*(independentPatterns.rbegin())).append(thisPattern);
    }
    else {
      independentPatterns.push_back(thisPattern);
    }
  }

  size_t numPatterns = independentPatterns.size();
  if (numPatterns > 1) {
    for (size_t p = 0; p < (numPatterns - 1); ++p) {
      patternString += "(?=" + independentPatterns[p] + ")";
    }
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
  std::vector<std::string> rulesFiles;
  try {
    rulesFiles = parseCommandLineOptions(argc, argv);
  }
  catch (po::error& pe) {
    std::cerr << pe.what();
    return 1;
  }
  std::vector<std::string> allOptions = parseRulesFiles(rulesFiles);

  pcrecpp::RE sidPattern("sid:(\\d+);");
  pcrecpp::RE contentPattern("((content|pcre):.*)(content:|pcre:|$)", pcrecpp::RE_Options(PCRE_UNGREEDY)); 

  boost::bimap<std::string, size_t> separatorKeywords(getSeparatorKeywordIndices());
  std::string separatorString = "(";
  for (boost::bimap<std::string, size_t>::left_const_iterator sk = separatorKeywords.left.begin(); sk != separatorKeywords.left.end(); ++sk) {
    separatorString += (sk->first + "|");
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

  for (std::vector<std::string>::const_iterator option = allOptions.begin(); option != allOptions.end(); ++option) {
    size_t sid;
    if (!sidPattern.PartialMatch(*option, &sid)) {
      throw std::runtime_error("Encountered a rule with no SID!");
    }
    pcrecpp::StringPiece optionString(*option);
    std::string thisContent, type, nextContent;
    std::map<size_t, std::vector<std::string> > contentVectors;
    while (!optionString.empty() && contentPattern.FindAndConsume(&optionString, &thisContent, &type, &nextContent)) {
      size_t index = 0;
      if (type == "content") {
        std::string keyword;
        if (keywordPattern.PartialMatch(thisContent, &keyword)) {
          index = (separatorKeywords.left.find(keyword))->second;
        }
        contentVectors[index].push_back(thisContent);
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
        contentVectors[index].push_back(pcreString);
      }
      nextContent += optionString.as_string();
      optionString.set(nextContent.c_str());
    }

    std::map<size_t, std::string> patternMap;
    for (std::map<size_t, std::vector<std::string> >::const_iterator content = contentVectors.begin(); content != contentVectors.end(); ++content) {
      try {
        std::string separatorKeyword = "payload";
        if (content->first > 0) {
          separatorKeyword = (separatorKeywords.right.find(content->first))->second;
        }
        std::string patternString = getContentPattern(content->second);
        std::cout << "Pattern to be searched in " << separatorKeyword << " for rule with SID " << sid << ": " << patternString << std::endl;
        patternMap.insert(std::make_pair(content->first, patternString));
      }
      catch (std::runtime_error& e) {
        std::cerr << std::endl;
        std::cerr << "Getting pattern for rule with SID " << sid << " failed." << std::endl;
        std::cerr << e.what() << std::endl << std::endl;
      }
    }
  }
  return 0;
}
