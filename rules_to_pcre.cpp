#include <fstream>
#include <iostream>
#include <map>
#include <string>

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
    std::cout << desc << std::endl;
    throw po::error("");
  }
  if ((vm.count("file") > 0) && (vm.count("directory") > 0)) {
    std::cout << "Files and directory can't be specified in combination." << std::endl;
    std::cout << "Please use only one of the options." << std::endl;
    std::cout << desc << std::endl;
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
          std::cout << keyword << " is not supported." << std::endl;
          std::cout << "Skipping rule " << rule << std::endl;
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
 * XXX: Work in progress.
 * This function returns a pattern for a given vector of pattern specifiers.
 * The pattern specifiers can be a combination of 'content's and 'pcre's.
 */
std::string
getContentPattern (const std::vector<std::string>& patternVector)
{
  std::string patternString;
  pcrecpp::RE paramPattern("(offset|depth|distance|within):(\\d+)");
  for (std::vector<std::string>::const_iterator pattern = patternVector.begin(); pattern != patternVector.end(); ++pattern) {
    pcrecpp::StringPiece pString(*pattern);
    std::string param;
    int value;
    while (paramPattern.FindAndConsume(&pString, &param, &value)) {
      std::cout << param << " = " << value << std::endl;
    }
    std::cout << *pattern << std::endl;
  }
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
    std::cout << pe.what();
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
  separatorString = "(.*\\/\\w*" + separatorString + "\\w*)";
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
        std::string pcreString, modifier;
        if (pcrePattern.Consume(&contentString, &pcreString, &modifier)) {
          std::cout << "pcre --> " << pcreString << " " << modifier << std::endl;
          if (!modifier.empty()) {
            index = (separatorModifiers.find(modifier[0]))->second;
            pcreString = pcreString.replace(pcreString.find(modifier), 1, "");
          }
          contentVectors[index].push_back(pcreString);
        }
      }
      nextContent += optionString.as_string();
      optionString.set(nextContent.c_str());
    }
    std::map<size_t, std::string> patternMap;
    for (std::map<size_t, std::vector<std::string> >::const_iterator content = contentVectors.begin(); content != contentVectors.end(); ++content) {
      std::string patternString = getContentPattern(content->second);
      patternMap.insert(std::make_pair(content->first, patternString));
    }
    std::cout << std::endl;
  }
  return 0;
}
