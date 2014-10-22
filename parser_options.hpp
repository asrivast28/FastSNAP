#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;

/**
 * This is a utility class for parsing command line arguments.
 */
class ParserOptions {
public:
  ParserOptions()
    : m_desc("Snort rules file parser options"),
    m_rulesFiles(), m_writeFiles(false)
  {
    po::options_description desc;
    m_desc.add_options()
      ("help,h", "Print this message.")
      ("file,f", po::value<std::vector<std::string> >(&m_rulesFiles), "Snort rules file(s) to be parsed.")
      ("directory,d", po::value<std::string>(), "Directory containing *.rules files.")
      ("writefiles", po::value<bool>(&m_writeFiles)->zero_tokens(), "Flag for specifying if the output should be written to a set of files.")
      ;
  }

  void parse(int argc, char** argv)
  {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, m_desc), vm);
    po::notify(vm);    
    
    if ((argc == 1) || (vm.count("help") > 0)) {
      std::cerr << m_desc << std::endl;
      throw po::error("");
    }
    if ((vm.count("file") > 0) && (vm.count("directory") > 0)) {
      std::cerr << "Files and directory can't be specified in combination." << std::endl;
      std::cerr << "Please use only one of the options." << std::endl;
      std::cerr << m_desc << std::endl;
      throw po::error("");
    }
    else if (vm.count("directory") == 1) {
      std::string directory = vm["directory"].as<std::string>();
      if (fs::exists(directory)) {
        for (fs::directory_iterator it(directory); it != fs::directory_iterator(); ++it) {
          if (it->path().extension().string() == ".rules") {
            m_rulesFiles.push_back(it->path().string());
          }
        }
      }
    }
  }

  const std::vector<std::string>& rulesFiles() const { return m_rulesFiles; }

  bool writeFiles() const { return m_writeFiles; }
  
private:
  po::options_description m_desc;
  std::vector<std::string> m_rulesFiles;
  bool m_writeFiles;
};