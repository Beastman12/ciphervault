// CipherVault - command line interface
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "ciphervault/clipboard.hpp"
#include "ciphervault/crypto/random.hpp"
#include "ciphervault/crypto/secure_memory.hpp"
#include "ciphervault/csv.hpp"
#include "ciphervault/entry.hpp"
#include "ciphervault/generator.hpp"
#include "ciphervault/selftest.hpp"
#include "ciphervault/strength.hpp"
#include "ciphervault/terminal.hpp"
#include "ciphervault/util.hpp"
#include "ciphervault/vault.hpp"

namespace ciphervault {
namespace {

constexpr const char* kVersion = "1.0.0";
constexpr int kClipboardSeconds = 30;
constexpr std::size_t kMinMasterLength = 12;

struct UsageError : std::runtime_error {
    explicit UsageError(const std::string& message) : std::runtime_error(message) {}
};

struct CliError : std::runtime_error {
    explicit CliError(const std::string& message) : std::runtime_error(message) {}
};

bool g_color = false;

std::string paint(const char* code, std::string_view text) {
    if (!g_color) return std::string(text);
    return std::string(code) + std::string(text) + "\x1b[0m";
}
std::string bold(std::string_view s) { return paint("\x1b[1m", s); }
std::string dim(std::string_view s) { return paint("\x1b[2m", s); }
std::string red(std::string_view s) { return paint("\x1b[31m", s); }
std::string green(std::string_view s) { return paint("\x1b[32m", s); }
std::string yellow(std::string_view s) { return paint("\x1b[33m", s); }
std::string cyan(std::string_view s) { return paint("\x1b[36m", s); }

void print_banner() {
    std::cout << "\n" << bold("  CipherVault") << dim("  -  encrypted credentials, on your machine") << "\n\n";
}

void print_usage() {
    print_banner();
    std::cout << "Usage: " << bold("ciphervault") << " [global options] <command> [options]\n\n"
              << "Commands:\n"
              << "  init                 Create a new encrypted vault\n"
              << "  add                  Add a credential (interactive prompts)\n"
              << "  list                 List all credentials\n"
              << "  search <terms...>    Search title, username, URL, notes and tags\n"
              << "  get <id|terms...>    Show or copy one credential\n"
              << "  edit <id>            Update a credential\n"
              << "  rm <id>              Delete a credential\n"
              << "  gen                  Generate a strong random password\n"
              << "  audit                Report weak, reused and stale passwords\n"
              << "  passwd               Change the master password\n"
              << "  export <file.csv>    Export decrypted data (explicit confirmation)\n"
              << "  import <file.csv>    Import credentials from CSV\n"
              << "  info                 Show vault metadata\n"
              << "  backup [file]        Copy the encrypted vault file\n"
              << "  selftest             Run the built-in crypto known-answer tests\n"
              << "  help [command]       Show help\n\n"
              << "Global options:\n"
              << "  --vault <path>       Vault location (env: CIPHERVAULT_PATH)\n"
              << "  --no-color           Disable ANSI colors\n"
              << "  -h, --help           Show this help\n"
              << "  -V, --version        Show version\n\n"
              << "Default vault: " << dim(path_to_display(default_vault_path())) << "\n\n"
              << "Examples:\n"
              << dim("  ciphervault init\n")
              << dim("  ciphervault add --title GitHub --username octocat --generate\n")
              << dim("  ciphervault search github\n")
              << dim("  ciphervault get github --copy\n")
              << dim("  ciphervault gen --length 24\n");
}

bool print_command_help(const std::string& command) {
    if (command == "init") {
        std::cout << "Usage: ciphervault init [--iterations N] [--force]\n\n"
                     "Creates a new vault. You will be asked for a master password\n"
                     "(minimum 12 characters). There is no recovery: if you forget it,\n"
                     "the data cannot be decrypted.\n\n"
                     "  --iterations N   PBKDF2 rounds (default 210000)\n"
                     "  --force          Replace an existing vault (keeps a .bak copy)\n";
    } else if (command == "add") {
        std::cout << "Usage: ciphervault add [options]\n\n"
                     "Missing fields are prompted for when stdin is a terminal.\n\n"
                     "  --title T        Entry title (required)\n"
                     "  --username U     Account name\n"
                     "  --password P     Password (omit to be prompted)\n"
                     "  --url URL        Site or service URL\n"
                     "  --notes N        Free-form notes\n"
                     "  --tags a,b       Comma separated tags\n"
                     "  --generate       Generate a password instead of prompting\n"
                     "  --length N       Generated password length (default 20)\n"
                     "  --no-symbols     Only use letters and digits\n"
                     "  --no-ambiguous   Exclude characters such as I, l, 1, O, 0\n";
    } else if (command == "get") {
        std::cout << "Usage: ciphervault get <id|terms...> [options]\n\n"
                     "  --show           Print the password\n"
                     "  --copy           Copy the password to the clipboard\n"
                     "  --stdout         Print only the password (for scripts)\n"
                     "  --field NAME     Print only title, username, password, url, notes, tags\n\n"
                     "By default the password is copied and cleared after "
                  << kClipboardSeconds << " seconds.\n";
    } else if (command == "gen") {
        std::cout << "Usage: ciphervault gen [--length N] [--count N] [--copy] [options]\n\n"
                     "  --length N       Password length (default 20)\n"
                     "  --count N        Number of passwords (default 1)\n"
                     "  --copy           Copy the first password to the clipboard\n"
                     "  --no-symbols     Only letters and digits\n"
                     "  --no-uppercase   No uppercase letters\n"
                     "  --no-lowercase   No lowercase letters\n"
                     "  --no-digits      No digits\n"
                     "  --no-ambiguous   Exclude I, l, 1, O, 0 and similar\n";
    } else if (command == "search") {
        std::cout << "Usage: ciphervault search <terms...>\n\n"
                     "All terms must match (AND). Matching is case-insensitive across\n"
                     "title, username, URL, notes and tags.\n";
    } else if (command == "list") {
        std::cout << "Usage: ciphervault list [--sort title|updated|created]\n";
    } else if (command == "edit") {
        std::cout << "Usage: ciphervault edit <id> [--title T] [--username U] [--password P]\n"
                     "       [--url URL] [--notes N] [--tags a,b] [--generate] [--length N]\n\n"
                     "With no field options, every field is prompted for and the current\n"
                     "value is shown as the default.\n";
    } else if (command == "rm") {
        std::cout << "Usage: ciphervault rm <id> [--yes]\n";
    } else if (command == "audit") {
        std::cout << "Usage: ciphervault audit\n\n"
                     "Reports weak passwords, passwords reused across entries and\n"
                     "credentials that have not been updated in over a year.\n";
    } else if (command == "passwd") {
        std::cout << "Usage: ciphervault passwd\n\n"
                     "Re-encrypts the vault with a new master password and a new salt.\n";
    } else if (command == "export") {
        std::cout << "Usage: ciphervault export <file.csv> [--yes]\n\n"
                     "Writes every credential in plain text. You must type EXPORT to\n"
                     "confirm. Delete the file immediately after use.\n";
    } else if (command == "import") {
        std::cout << "Usage: ciphervault import <file.csv>\n\n"
                     "Accepts the CSV format produced by export (or compatible files\n"
                     "with title, username, password, url, notes and tags columns).\n";
    } else if (command == "info") {
        std::cout << "Usage: ciphervault info\n";
    } else if (command == "backup") {
        std::cout << "Usage: ciphervault backup [destination]\n\n"
                     "Copies the encrypted vault. The copy is useless without the\n"
                     "master password.\n";
    } else if (command == "selftest") {
        std::cout << "Usage: ciphervault selftest\n";
    } else if (command == "help") {
        std::cout << "Usage: ciphervault help [command]\n";
    } else {
        return false;
    }
    std::cout << "\nGlobal options: --vault <path>, --no-color, --help, --version\n";
    return true;
}

struct Globals {
    std::filesystem::path vault_path;
    bool color = true;
    bool help = false;
    bool version = false;
};

Globals parse_globals(int argc, char** argv, std::vector<std::string>& rest) {
    Globals globals;
    globals.vault_path = default_vault_path();
    bool color_requested = true;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--vault") {
            if (i + 1 >= argc) throw UsageError("--vault requires a path");
            globals.vault_path = std::filesystem::u8path(argv[++i]);
        } else if (starts_with(arg, "--vault=")) {
            globals.vault_path = std::filesystem::u8path(arg.substr(8));
        } else if (arg == "--no-color") {
            color_requested = false;
        } else if (arg == "--color") {
            color_requested = true;
        } else if (arg == "--help" || arg == "-h") {
            globals.help = true;
        } else if (arg == "--version" || arg == "-V") {
            globals.version = true;
        } else {
            rest.push_back(arg);
        }
    }

    const std::string term_env = to_lower(get_env("TERM"));
    globals.color = color_requested && term::stdout_is_tty() && term_env != "dumb";
    return globals;
}

struct ParsedArgs {
    std::vector<std::string> positional;
    std::map<std::string, std::string> values;
    std::set<std::string> switches;

    bool has(const std::string& name) const { return switches.count(name) != 0; }
    bool has_value(const std::string& name) const { return values.count(name) != 0; }
    std::string value(const std::string& name, const std::string& fallback = {}) const {
        const auto it = values.find(name);
        return it == values.end() ? fallback : it->second;
    }
};

ParsedArgs parse_args(const std::vector<std::string>& tokens,
                      const std::set<std::string>& value_flags) {
    ParsedArgs args;
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (starts_with(token, "--")) {
            const std::size_t eq = token.find('=');
            if (eq != std::string::npos) {
                args.values[token.substr(2, eq - 2)] = token.substr(eq + 1);
                continue;
            }
            const std::string name = token.substr(2);
            if (value_flags.count(name) != 0) {
                if (i + 1 >= tokens.size()) {
                    throw UsageError("option --" + name + " requires a value");
                }
                args.values[name] = tokens[++i];
            } else {
                args.switches.insert(name);
            }
        } else if (token == "-h") {
            args.switches.insert("help");
        } else {
            args.positional.push_back(token);
        }
    }
    return args;
}

void validate_args(const ParsedArgs& args, const std::set<std::string>& allowed_switches,
                   const std::set<std::string>& allowed_values) {
    for (const auto& [name, unused] : args.values) {
        (void)unused;
        if (allowed_values.count(name) == 0) throw UsageError("unknown option --" + name);
    }
    for (const auto& name : args.switches) {
        if (name != "help" && allowed_switches.count(name) == 0) {
            throw UsageError("unknown option --" + name);
        }
    }
}

std::uint32_t parse_u32(const std::string& text, const std::string& name, std::uint32_t min_value,
                        std::uint32_t max_value) {
    if (text.empty()) throw UsageError(name + " must be a number");
    std::size_t consumed = 0;
    unsigned long value = 0;
    try {
        value = std::stoul(text, &consumed);
    } catch (const std::exception&) {
        throw UsageError(name + " must be a number");
    }
    if (consumed != text.size() || value < min_value || value > max_value) {
        throw UsageError(name + " must be between " + std::to_string(min_value) + " and " +
                         std::to_string(max_value));
    }
    return static_cast<std::uint32_t>(value);
}

std::string ask_line(const std::string& label, const std::string& current = {}) {
    const std::string prompt =
        current.empty() ? label + ": " : label + " [" + current + "]: ";
    const std::string line = trim(term::read_line(prompt));
    return line.empty() ? current : line;
}

std::string ask_password(const std::string& label, const std::string& current = {}) {
    const std::string prompt =
        current.empty() ? label + ": " : label + " [leave empty to keep]: ";
    std::string line = term::read_password(prompt);
    if (line.empty()) return current;
    return line;
}

bool confirm(const std::string& question) {
    const std::string answer = to_lower(trim(term::read_line(question + " [y/N]: ")));
    return answer == "y" || answer == "yes";
}

std::string mask_password(std::string_view password) {
    const std::size_t shown = std::min<std::size_t>(password.size(), 16);
    return std::string(shown, '*');
}

std::string strength_text(const StrengthResult& result) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(0) << result.entropy_bits << " bits";
    const std::string label = result.label + " (" + out.str() + ")";
    if (result.score >= 3) return green(label);
    if (result.score == 2) return yellow(label);
    return red(label);
}

void print_strength(const StrengthResult& result) {
    std::cout << "  Strength: " << strength_text(result) << "\n";
    for (std::size_t i = 0; i < result.warnings.size() && i < 3; ++i) {
        std::cout << "  " << dim("! " + result.warnings[i]) << "\n";
    }
}

std::string truncate_cell(std::string text, std::size_t max_len) {
    for (char& c : text) {
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    if (text.size() <= max_len) return text;
    if (max_len <= 3) return text.substr(0, max_len);
    return text.substr(0, max_len - 3) + "...";
}

void print_entries(const std::vector<const Entry*>& entries) {
    if (entries.empty()) {
        std::cout << dim("  No credentials found.") << "\n";
        return;
    }

    const std::vector<std::string> headers = {"ID", "TITLE", "USERNAME", "URL", "UPDATED"};
    const std::vector<std::size_t> limits = {8, 28, 24, 32, 13};
    std::vector<std::vector<std::string>> rows;
    rows.reserve(entries.size());
    for (const Entry* entry : entries) {
        rows.push_back({short_id(entry->id), entry->title, entry->username, entry->url,
                        format_relative_time(entry->modified)});
    }

    std::vector<std::size_t> widths(headers.size());
    for (std::size_t c = 0; c < headers.size(); ++c) {
        widths[c] = headers[c].size();
        for (const auto& row : rows) {
            const std::string cell = truncate_cell(row[c], limits[c]);
            widths[c] = std::max(widths[c], cell.size());
        }
    }

    auto print_row = [&](const std::vector<std::string>& cells) {
        std::ostringstream line;
        for (std::size_t c = 0; c < cells.size(); ++c) {
            const std::string cell = truncate_cell(cells[c], limits[c]);
            if (c + 1 == cells.size()) {
                line << cell;
            } else {
                line << std::left << std::setw(static_cast<int>(widths[c] + 2)) << cell;
            }
        }
        return line.str();
    };

    std::cout << dim(print_row(headers)) << "\n";
    std::ostringstream underline;
    for (std::size_t c = 0; c < headers.size(); ++c) {
        underline << std::string(widths[c] + (c + 1 == headers.size() ? 0 : 2), '-');
    }
    std::cout << dim(underline.str()) << "\n";
    for (const auto& row : rows) std::cout << print_row(row) << "\n";
    std::cout << dim("  " + std::to_string(entries.size()) + " credential(s)") << "\n";
}

void print_details(const Entry& entry, bool show_password) {
    const auto field = [](const std::string& label, const std::string& value) {
        std::cout << "  " << dim(label) << std::string(label.size() < 10 ? 10 - label.size() : 1, ' ')
                  << value << "\n";
    };

    field("Title", bold(entry.title));
    field("Username", entry.username);
    field("Password", show_password ? yellow(entry.password)
                                    : mask_password(entry.password) + dim("  (hidden)"));
    if (!entry.url.empty()) field("URL", cyan(entry.url));
    field("Tags", join(entry.tags, ", "));
    field("Created", format_timestamp(entry.created));
    field("Updated", format_timestamp(entry.modified) + "  " + dim("(" + format_relative_time(entry.modified) + ")"));
    field("ID", dim(entry.id));
    if (!entry.notes.empty()) {
        std::cout << "\n  " << dim("Notes") << "\n";
        std::istringstream notes(entry.notes);
        std::string line;
        while (std::getline(notes, line)) std::cout << "    " << line << "\n";
    }
    std::cout << "\n";
}

std::vector<const Entry*> resolve_entries(const Vault& vault, const std::string& selector) {
    std::vector<const Entry*> matches;
    if (selector.empty()) return matches;

    if (const Entry* exact = vault.find_by_id(selector)) {
        matches.push_back(exact);
        return matches;
    }

    const std::string needle = to_lower(selector);
    if (needle.size() >= 4) {
        for (const auto& entry : vault.entries()) {
            if (starts_with(to_lower(entry.id), needle)) matches.push_back(&entry);
        }
        if (!matches.empty()) return matches;
    }

    return search_entries(vault.entries(), selector);
}

const Entry& resolve_unique(const Vault& vault, const std::string& selector) {
    const auto matches = resolve_entries(vault, selector);
    if (matches.empty()) throw CliError("no credential matches '" + selector + "'");
    if (matches.size() > 1) {
        std::cerr << yellow("Multiple credentials match '" + selector + "':") << "\n\n";
        print_entries(matches);
        throw CliError("be more specific, or use the full id");
    }
    return *matches.front();
}

std::string entry_field(const Entry& entry, const std::string& field) {
    if (field == "title") return entry.title;
    if (field == "username") return entry.username;
    if (field == "password") return entry.password;
    if (field == "url") return entry.url;
    if (field == "notes") return entry.notes;
    if (field == "tags") return join(entry.tags, ",");
    if (field == "id") return entry.id;
    throw UsageError("unknown field '" + field + "'");
}

Vault unlock_vault(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        throw CliError("no vault found at " + path_to_display(path) +
                       "\nCreate one with: ciphervault init");
    }

    const std::string env_password = get_env("CIPHERVAULT_MASTER");
    if (!env_password.empty()) {
        std::cerr << yellow("warning: master password read from CIPHERVAULT_MASTER\n");
        return Vault::open(path, env_password);
    }

    const int attempts = term::stdin_is_tty() ? 3 : 1;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        const std::string password = term::read_password("Master password: ");
        if (password.empty()) throw CliError("master password is required");
        try {
            return Vault::open(path, password);
        } catch (const VaultError& error) {
            if (error.kind() != VaultErrorKind::Authentication || attempt == attempts) throw;
            std::cerr << red("Authentication failed.") << " " << (attempts - attempt)
                      << " attempt(s) left.\n";
        }
    }
    throw CliError("could not unlock the vault");
}

std::string choose_master_password(bool confirm_password) {
    const std::string env_password = get_env("CIPHERVAULT_MASTER");
    if (!env_password.empty()) {
        std::cerr << yellow("warning: master password read from CIPHERVAULT_MASTER\n");
        return env_password;
    }
    if (!term::stdin_is_tty()) {
        throw CliError(
            "an interactive terminal is required to choose a master password\n"
            "set CIPHERVAULT_MASTER for non-interactive use (development only)");
    }

    for (;;) {
        const std::string first = term::read_password("Choose a master password: ");
        if (first.size() < kMinMasterLength) {
            std::cerr << red("The master password must be at least " +
                             std::to_string(kMinMasterLength) + " characters.") << "\n";
            continue;
        }
        if (confirm_password) {
            const std::string second = term::read_password("Confirm master password: ");
            if (first != second) {
                std::cerr << red("Passwords do not match.") << "\n";
                continue;
            }
        }
        const StrengthResult strength = estimate_strength(first);
        if (strength.score <= 1) {
            std::cerr << yellow("This master password is weak: ") << strength_text(strength) << "\n";
            if (!confirm("Use it anyway?")) continue;
        }
        return first;
    }
}

GeneratorOptions generator_options_from(const ParsedArgs& args) {
    GeneratorOptions options;
    if (args.has_value("length")) {
        options.length = parse_u32(args.value("length"), "--length", 1, 1024);
    }
    options.use_symbols = !args.has("no-symbols");
    options.use_uppercase = !args.has("no-uppercase");
    options.use_lowercase = !args.has("no-lowercase");
    options.use_digits = !args.has("no-digits");
    options.exclude_ambiguous = args.has("no-ambiguous");
    return options;
}

std::vector<std::string> parse_tags(const std::string& raw) {
    std::vector<std::string> tags;
    for (const auto& part : split(raw, ',')) {
        const std::string tag = trim(part);
        if (!tag.empty() &&
            std::find(tags.begin(), tags.end(), tag) == tags.end()) {
            tags.push_back(tag);
        }
    }
    return tags;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

int cmd_init(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {"iterations"});
    validate_args(args, {"force"}, {"iterations"});
    if (!args.positional.empty()) throw UsageError("init does not take positional arguments");

    std::uint32_t iterations = Vault::kDefaultIterations;
    if (args.has_value("iterations")) {
        iterations = parse_u32(args.value("iterations"), "--iterations", Vault::kMinIterations,
                               Vault::kMaxIterations);
    }

    std::error_code ec;
    const bool exists = std::filesystem::exists(globals.vault_path, ec);
    if (exists && !args.has("force")) {
        throw CliError("a vault already exists at " + path_to_display(globals.vault_path) +
                       "\nuse --force to replace it (the old file is kept as .bak)");
    }
    if (exists) {
        backup_file(globals.vault_path);
        std::cout << yellow("Existing vault backed up to ") << path_to_display(globals.vault_path)
                  << ".bak\n";
    }

    std::cout << "Creating a vault at " << cyan(path_to_display(globals.vault_path)) << "\n";
    std::cout << dim("The master password is never stored. There is no recovery if you lose it.")
              << "\n\n";

    const std::string password = choose_master_password(true);
    Vault vault = Vault::create(globals.vault_path, password, iterations);

    std::cout << "\n" << green("Vault created.") << "\n"
              << "  Path:       " << path_to_display(globals.vault_path) << "\n"
              << "  Encryption: AES-256-GCM\n"
              << "  KDF:        PBKDF2-HMAC-SHA256, " << iterations << " rounds\n"
              << "  Vault id:   " << vault.vault_id() << "\n\n"
              << dim("Add your first credential with: ciphervault add") << "\n";
    return 0;
}

int cmd_add(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(
        tokens, {"title", "username", "password", "url", "notes", "tags", "length"});
    validate_args(args,
                  {"generate", "no-symbols", "no-uppercase", "no-lowercase", "no-digits",
                   "no-ambiguous"},
                  {"title", "username", "password", "url", "notes", "tags", "length"});
    if (!args.positional.empty()) throw UsageError("add does not take positional arguments");
    if (args.has("generate") && args.has_value("password")) {
        throw UsageError("use either --password or --generate, not both");
    }

    Vault vault = unlock_vault(globals.vault_path);

    const bool interactive = term::stdin_is_tty();
    Entry entry;
    entry.title = trim(args.value("title"));
    if (entry.title.empty()) {
        if (!interactive) throw UsageError("--title is required when stdin is not a terminal");
        entry.title = ask_line("Title");
    }
    if (entry.title.empty()) throw CliError("a title is required");

    entry.username = args.value("username");
    if (!args.has_value("username") && interactive) entry.username = ask_line("Username (optional)");

    bool generated = false;
    if (args.has_value("password")) {
        entry.password = args.value("password");
    } else if (args.has("generate")) {
        entry.password = generate_password(generator_options_from(args));
        generated = true;
    } else if (interactive) {
        entry.password = ask_password("Password (leave empty to generate)");
        if (entry.password.empty()) {
            entry.password = generate_password(generator_options_from(args));
            generated = true;
        }
    } else {
        throw UsageError("provide --password or --generate when stdin is not a terminal");
    }

    entry.url = args.value("url");
    entry.notes = args.value("notes");
    if (args.has_value("tags")) entry.tags = parse_tags(args.value("tags"));
    if (interactive && !args.has_value("url")) entry.url = ask_line("URL (optional)", entry.url);
    if (interactive && !args.has_value("notes")) {
        entry.notes = ask_line("Notes (optional)", entry.notes);
    }
    if (interactive && !args.has_value("tags")) {
        const std::string tags = ask_line("Tags (comma separated, optional)", join(entry.tags, ", "));
        if (!tags.empty()) entry.tags = parse_tags(tags);
    }

    const std::string id = vault.add_entry(std::move(entry));
    vault.save();

    const Entry* saved = vault.find_by_id(id);
    std::cout << green("Added ") << saved->title << dim(" (" + short_id(id) + ")") << "\n";
    if (generated) {
        std::cout << "  Password: " << yellow(saved->password) << "\n";
        print_strength(estimate_strength(saved->password));
        std::cout << dim("  Save it now: the password is only shown on request.")
                  << "\n";
    }
    return 0;
}

int cmd_list(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {"sort"});
    validate_args(args, {}, {"sort"});
    if (!args.positional.empty()) throw UsageError("list does not take positional arguments");

    Vault vault = unlock_vault(globals.vault_path);
    const std::string sort = args.value("sort", "title");
    std::vector<const Entry*> entries;
    entries.reserve(vault.entries().size());
    for (const auto& entry : vault.entries()) entries.push_back(&entry);

    if (sort == "title") {
        sort_entry_pointers(entries);
    } else if (sort == "updated" || sort == "created") {
        const bool by_updated = sort == "updated";
        std::sort(entries.begin(), entries.end(), [by_updated](const Entry* a, const Entry* b) {
            return by_updated ? a->modified > b->modified : a->created > b->created;
        });
    } else {
        throw UsageError("--sort must be title, updated or created");
    }

    if (entries.empty()) {
        std::cout << "Your vault is empty. Add a credential with: " << bold("ciphervault add")
                  << "\n";
        return 0;
    }
    print_entries(entries);
    return 0;
}

int cmd_search(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (args.positional.empty()) throw UsageError("search needs at least one term");

    const std::string query = join(args.positional, " ");
    Vault vault = unlock_vault(globals.vault_path);
    const auto matches = search_entries(vault.entries(), query);
    if (matches.empty()) {
        std::cout << "No credentials match " << bold("'" + query + "'") << ".\n";
        return 0;
    }
    std::cout << "Matches for " << bold("'" + query + "'") << ":\n\n";
    print_entries(matches);
    return 0;
}

int cmd_get(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {"field"});
    validate_args(args, {"show", "copy", "stdout"}, {"field"});
    if (args.positional.empty()) throw UsageError("get needs an id or search terms");

    const std::string selector = join(args.positional, " ");
    Vault vault = unlock_vault(globals.vault_path);
    const Entry& entry = resolve_unique(vault, selector);

    const std::string field = args.value("field");
    if (!field.empty()) {
        const std::string value = entry_field(entry, field);
        if (args.has("copy")) {
            if (!clipboard_copy_with_timeout(value, kClipboardSeconds)) {
                throw CliError("clipboard is not available");
            }
            std::cerr << dim("copied to clipboard (clears in " + std::to_string(kClipboardSeconds) +
                             "s)")
                      << "\n";
        } else {
            std::cout << value << "\n";
        }
        return 0;
    }

    if (args.has("stdout")) {
        std::cout << entry.password << "\n";
        return 0;
    }

    const bool show = args.has("show");
    print_details(entry, show);

    bool copied = false;
    if (args.has("copy") || (term::stdout_is_tty() && !show)) {
        if (clipboard_copy_with_timeout(entry.password, kClipboardSeconds)) {
            copied = true;
            std::cout << green("Password copied to the clipboard.") << " "
                      << dim("It will be cleared in " + std::to_string(kClipboardSeconds) +
                             " seconds if unchanged.")
                      << "\n";
        } else if (args.has("copy")) {
            std::cerr << yellow("Clipboard is not available on this system.") << "\n";
        }
    }

    if (!show && !copied) {
        std::cout << dim("Use --show to reveal the password or --copy to copy it.") << "\n";
    }
    return 0;
}

int cmd_edit(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(
        tokens, {"title", "username", "password", "url", "notes", "tags", "length"});
    validate_args(args,
                  {"generate", "no-symbols", "no-uppercase", "no-lowercase", "no-digits",
                   "no-ambiguous"},
                  {"title", "username", "password", "url", "notes", "tags", "length"});
    if (args.positional.empty()) throw UsageError("edit needs the id of a credential");
    if (args.has("generate") && args.has_value("password")) {
        throw UsageError("use either --password or --generate, not both");
    }

    Vault vault = unlock_vault(globals.vault_path);
    const std::string selector = join(args.positional, " ");
    const Entry& existing = resolve_unique(vault, selector);
    Entry updated = existing;

    const bool any_field = args.has_value("title") || args.has_value("username") ||
                           args.has_value("password") || args.has_value("url") ||
                           args.has_value("notes") || args.has_value("tags");
    const bool interactive = term::stdin_is_tty();

    if (!any_field && !args.has("generate")) {
        if (!interactive) throw UsageError("no fields to update");
        std::cout << dim("Press Enter to keep the current value.") << "\n";
        updated.title = ask_line("Title", updated.title);
        updated.username = ask_line("Username", updated.username);
        updated.url = ask_line("URL", updated.url);
        updated.notes = ask_line("Notes", updated.notes);
        const std::string tags = ask_line("Tags (comma separated)", join(updated.tags, ", "));
        if (!tags.empty()) updated.tags = parse_tags(tags);

        std::string password = term::read_password("New password (leave empty to keep, '-' to generate): ");
        if (password == "-") {
            password = generate_password(generator_options_from(args));
            std::cout << "  Generated: " << yellow(password) << "\n";
            print_strength(estimate_strength(password));
        }
        if (!password.empty()) updated.password = password;
    } else {
        if (args.has_value("title")) updated.title = trim(args.value("title"));
        if (args.has_value("username")) updated.username = args.value("username");
        if (args.has_value("password")) updated.password = args.value("password");
        if (args.has_value("url")) updated.url = args.value("url");
        if (args.has_value("notes")) updated.notes = args.value("notes");
        if (args.has_value("tags")) updated.tags = parse_tags(args.value("tags"));
        if (args.has("generate")) {
            updated.password = generate_password(generator_options_from(args));
            std::cout << "  Generated: " << yellow(updated.password) << "\n";
            print_strength(estimate_strength(updated.password));
        }
    }

    if (updated.title.empty()) throw CliError("a title is required");
    if (!vault.update_entry(existing.id, std::move(updated))) {
        throw CliError("credential could not be updated");
    }
    vault.save();
    std::cout << green("Updated ") << existing.title << dim(" (" + short_id(existing.id) + ")") << "\n";
    return 0;
}

int cmd_rm(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {"yes"}, {});
    if (args.positional.empty()) throw UsageError("rm needs the id of a credential");

    Vault vault = unlock_vault(globals.vault_path);
    const std::string selector = join(args.positional, " ");
    const Entry& entry = resolve_unique(vault, selector);

    if (!args.has("yes")) {
        if (!term::stdin_is_tty()) throw CliError("pass --yes to delete without confirmation");
        if (!confirm("Delete '" + entry.title + "'" +
                     (entry.username.empty() ? "" : " (" + entry.username + ")") + "?")) {
            std::cout << "Cancelled.\n";
            return 0;
        }
    }

    const std::string title = entry.title;
    const std::string id = entry.id;
    if (!vault.remove_entry(id)) throw CliError("credential could not be deleted");
    vault.save();
    std::cout << green("Deleted ") << title << dim(" (" + short_id(id) + ")") << "\n";
    return 0;
}

int cmd_gen(const Globals& globals, const std::vector<std::string>& tokens) {
    (void)globals;
    ParsedArgs args = parse_args(tokens, {"length", "count"});
    validate_args(args,
                  {"no-symbols", "no-uppercase", "no-lowercase", "no-digits", "no-ambiguous",
                   "copy"},
                  {"length", "count"});
    if (!args.positional.empty()) throw UsageError("gen does not take positional arguments");

    GeneratorOptions options = generator_options_from(args);
    const std::uint32_t count = args.has_value("count")
                                    ? parse_u32(args.value("count"), "--count", 1, 100)
                                    : 1;

    if (count == 1) {
        const std::string password = generate_password(options);
        std::cout << password << "\n";
        print_strength(estimate_strength(password));
        if (args.has("copy")) {
            if (clipboard_copy_with_timeout(password, kClipboardSeconds)) {
                std::cout << green("Copied to clipboard.") << dim(" (clears in " +
                                                                  std::to_string(kClipboardSeconds) +
                                                                  "s)")
                          << "\n";
            } else {
                std::cout << yellow("Clipboard is not available.") << "\n";
            }
        }
    } else {
        for (std::uint32_t i = 0; i < count; ++i) {
            std::cout << generate_password(options) << "\n";
        }
        if (args.has("copy")) {
            std::cout << yellow("--copy is ignored when --count is greater than 1.") << "\n";
        }
    }
    return 0;
}

int cmd_audit(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (!args.positional.empty()) throw UsageError("audit does not take positional arguments");

    Vault vault = unlock_vault(globals.vault_path);
    const auto& entries = vault.entries();
    if (entries.empty()) {
        std::cout << "Your vault is empty.\n";
        return 0;
    }

    std::vector<const Entry*> weak;
    std::vector<const Entry*> stale;
    std::vector<const Entry*> empty_passwords;
    std::map<std::string, std::vector<const Entry*>> by_password;

    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    for (const auto& entry : entries) {
        if (entry.password.empty()) {
            empty_passwords.push_back(&entry);
        } else {
            by_password[entry.password].push_back(&entry);
        }
        const StrengthResult strength = estimate_strength(entry.password);
        if (strength.score <= 1 || strength.entropy_bits < 50.0) weak.push_back(&entry);
        if (entry.modified > 0 && now - entry.modified > 365LL * 24 * 3600) stale.push_back(&entry);
    }

    std::size_t reused_groups = 0;
    std::size_t reused_entries = 0;
    for (const auto& [password, group] : by_password) {
        (void)password;
        if (group.size() > 1) {
            ++reused_groups;
            reused_entries += group.size();
        }
    }

    std::cout << bold("Vault audit") << "\n";
    std::cout << dim("  " + std::to_string(entries.size()) + " credential(s) checked") << "\n\n";

    auto print_group = [](const char* heading, const std::vector<const Entry*>& group) {
        std::cout << yellow(heading) << " (" << group.size() << ")\n";
        for (const Entry* entry : group) {
            std::cout << "  - " << entry->title;
            if (!entry->username.empty()) std::cout << " <" << entry->username << ">";
            std::cout << "  " << dim(short_id(entry->id)) << "\n";
        }
        std::cout << "\n";
    };

    if (!weak.empty()) print_group("Weak passwords", weak);
    if (reused_groups > 0) {
        std::cout << yellow("Reused passwords") << " (" << reused_entries << " entries, "
                  << reused_groups << " shared password(s))\n";
        for (const auto& [password, group] : by_password) {
            (void)password;
            if (group.size() <= 1) continue;
            std::cout << "  -";
            for (const Entry* entry : group) std::cout << " " << entry->title;
            std::cout << "\n";
        }
        std::cout << "\n";
    }
    if (!stale.empty()) print_group("Not updated in over a year", stale);
    if (!empty_passwords.empty()) print_group("Empty passwords", empty_passwords);

    const bool clean =
        weak.empty() && reused_groups == 0 && stale.empty() && empty_passwords.empty();
    if (clean) {
        std::cout << green("No issues found.") << " Your passwords look healthy.\n";
    } else {
        std::cout << dim("Fix weak or reused passwords with: ciphervault edit <id> --generate")
                  << "\n";
    }
    return 0;
}

int cmd_passwd(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (!args.positional.empty()) throw UsageError("passwd does not take positional arguments");

    Vault vault = unlock_vault(globals.vault_path);
    if (!term::stdin_is_tty()) {
        throw CliError("changing the master password requires an interactive terminal");
    }

    const std::string current = term::read_password("Current master password: ");
    if (!vault.verify_master_password(current)) {
        throw CliError("current master password is incorrect");
    }

    const std::string next = choose_master_password(true);
    vault.change_master_password(current, next);
    std::cout << green("Master password changed.") << "\n"
              << dim("The vault was re-encrypted with a new random salt. The old .bak file was "
                     "removed because it was encrypted with the previous password.")
              << "\n";
    return 0;
}

std::string one_line(std::string text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c == '\n') out += "\\n";
        else if (c != '\r') out.push_back(c);
    }
    return out;
}

std::string restore_lines(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 1 < text.size() && text[i + 1] == 'n') {
            out.push_back('\n');
            ++i;
        } else {
            out.push_back(text[i]);
        }
    }
    return out;
}

std::int64_t parse_timestamp(const std::string& text) {
    if (text.empty() || text == "-") return 0;
    std::tm tm_buf{};
    std::istringstream in(text);
    in >> std::get_time(&tm_buf, "%Y-%m-%d %H:%M");
    if (in.fail()) return 0;
    tm_buf.tm_isdst = -1;
    const std::time_t value = std::mktime(&tm_buf);
    return value <= 0 ? 0 : static_cast<std::int64_t>(value);
}

int cmd_export(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {"yes"}, {});
    if (args.positional.size() != 1) throw UsageError("export needs exactly one output file");

    const std::filesystem::path out_path = std::filesystem::u8path(args.positional.front());
    Vault vault = unlock_vault(globals.vault_path);

    std::cerr << red("WARNING:") << " this export contains every password in plain text.\n"
              << "Anyone who reads the file owns your accounts. Delete it after use.\n";
    if (!args.has("yes")) {
        if (!term::stdin_is_tty()) throw CliError("pass --yes to export in a non-interactive shell");
        const std::string answer = term::read_line("Type EXPORT to continue: ");
        if (answer != "EXPORT") {
            std::cout << "Cancelled.\n";
            return 0;
        }
    }

    std::ostringstream csv;
    csv << "title,username,password,url,notes,tags,created,modified\n";
    for (const auto& entry : vault.entries()) {
        csv << csv_row({entry.title, entry.username, entry.password, entry.url,
                        one_line(entry.notes), join(entry.tags, ";"),
                        entry.created > 0 ? format_timestamp(entry.created) : "",
                        entry.modified > 0 ? format_timestamp(entry.modified) : ""})
            << "\n";
    }

    const std::string text = csv.str();
    std::vector<std::uint8_t> bytes(text.begin(), text.end());
    atomic_write_file(out_path, bytes);
    secure_zero(bytes);

    std::cout << green("Exported ") << vault.entries().size() << " credential(s) to "
              << path_to_display(out_path) << "\n"
              << dim("Delete the file when you are done.") << "\n";
    return 0;
}

int cmd_import(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (args.positional.size() != 1) throw UsageError("import needs exactly one input file");

    const std::filesystem::path in_path = std::filesystem::u8path(args.positional.front());
    const auto raw = read_file(in_path);
    const std::string text(raw.begin(), raw.end());
    const char delimiter = detect_delimiter(text);
    auto rows = csv_parse(text, delimiter);
    if (rows.empty()) throw CliError("the CSV file is empty");

    // Drop trailing empty rows.
    while (!rows.empty() && rows.back().size() == 1 && trim(rows.back().front()).empty()) {
        rows.pop_back();
    }
    if (rows.empty()) throw CliError("the CSV file is empty");

    std::map<std::string, std::size_t> columns;
    const auto& header = rows.front();
    for (std::size_t i = 0; i < header.size(); ++i) {
        columns[to_lower(trim(header[i]))] = i;
    }
    if (columns.count("title") == 0) {
        throw CliError("CSV must have a 'title' column (found: " + join(header, ", ") + ")");
    }
    if (columns.count("password") == 0) {
        throw CliError("CSV must have a 'password' column");
    }

    auto cell = [&columns](const std::vector<std::string>& row, const std::string& name) {
        const auto it = columns.find(name);
        if (it == columns.end() || it->second >= row.size()) return std::string();
        return row[it->second];
    };

    Vault vault = unlock_vault(globals.vault_path);
    std::size_t imported = 0;
    std::size_t skipped = 0;

    for (std::size_t r = 1; r < rows.size(); ++r) {
        const auto& row = rows[r];
        if (row.size() == 1 && trim(row.front()).empty()) continue;
        Entry entry;
        entry.title = trim(cell(row, "title"));
        entry.username = cell(row, "username");
        entry.password = cell(row, "password");
        entry.url = cell(row, "url");
        entry.notes = restore_lines(cell(row, "notes"));
        entry.tags = parse_tags(cell(row, "tags"));
        entry.created = parse_timestamp(cell(row, "created"));
        entry.modified = parse_timestamp(cell(row, "modified"));
        if (entry.title.empty()) {
            ++skipped;
            continue;
        }

        bool duplicate = false;
        for (const auto& existing : vault.entries()) {
            if (iequals(existing.title, entry.title) &&
                iequals(existing.username, entry.username) &&
                existing.password == entry.password) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            ++skipped;
            continue;
        }

        vault.add_entry(std::move(entry));
        ++imported;
    }

    if (imported > 0) vault.save();
    std::cout << green("Imported ") << imported << " credential(s)";
    if (skipped > 0) std::cout << ", skipped " << skipped << " (duplicate or empty)";
    std::cout << ".\n";
    return 0;
}

int cmd_info(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (!args.positional.empty()) throw UsageError("info does not take positional arguments");

    Vault vault = unlock_vault(globals.vault_path);
    std::error_code ec;
    const std::uint64_t file_size =
        static_cast<std::uint64_t>(std::filesystem::file_size(globals.vault_path, ec));

    std::cout << bold("Vault information") << "\n"
              << "  Path:        " << path_to_display(globals.vault_path) << "\n"
              << "  Vault id:    " << vault.vault_id() << "\n"
              << "  Entries:     " << vault.entries().size() << "\n"
              << "  Created:     " << format_timestamp(vault.created()) << "\n"
              << "  Revision:    " << vault.revision() << "\n"
              << "  File size:   " << (ec ? std::string("unknown") : human_size(file_size)) << "\n"
              << "  Cipher:      AES-256-GCM (authenticated encryption)\n"
              << "  KDF:         PBKDF2-HMAC-SHA256\n"
              << "  KDF rounds:  " << vault.iterations() << "\n"
              << "  Format:      CipherVault v1\n";
    return 0;
}

int cmd_backup(const Globals& globals, const std::vector<std::string>& tokens) {
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (args.positional.size() > 1) throw UsageError("backup takes at most one destination");

    std::filesystem::path destination;
    if (args.positional.size() == 1) {
        destination = std::filesystem::u8path(args.positional.front());
    } else {
        std::ostringstream stamp;
        const std::time_t now = std::time(nullptr);
        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &now);
#else
        localtime_r(&now, &tm_buf);
#endif
        stamp << std::put_time(&tm_buf, "%Y%m%d-%H%M%S");
        destination = globals.vault_path;
        destination += ".backup-" + stamp.str();
    }

    std::error_code ec;
    if (!std::filesystem::exists(globals.vault_path, ec)) {
        throw CliError("no vault found at " + path_to_display(globals.vault_path));
    }
    if (std::filesystem::equivalent(globals.vault_path, destination, ec)) {
        throw CliError("backup destination is the vault itself");
    }
    ensure_private_directory(destination.parent_path());
    std::filesystem::copy_file(globals.vault_path, destination,
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) throw CliError("could not write backup: " + ec.message());
    set_owner_only_permissions(destination);
    std::cout << green("Backup written to ") << path_to_display(destination) << "\n"
              << dim("The backup is encrypted with the same master password.") << "\n";
    return 0;
}

int cmd_selftest(const Globals& globals, const std::vector<std::string>& tokens) {
    (void)globals;
    ParsedArgs args = parse_args(tokens, {});
    validate_args(args, {}, {});
    if (!args.positional.empty()) throw UsageError("selftest does not take positional arguments");

    std::cout << bold("CipherVault crypto self-test") << "\n";
    const bool ok = run_self_test();
    return ok ? 0 : 1;
}

}  // namespace

int run_cli(int argc, char** argv) {
    try {
        std::vector<std::string> rest;
        const Globals globals = parse_globals(argc, argv, rest);
        g_color = globals.color;

        if (globals.version) {
            std::cout << "ciphervault " << kVersion << "\n";
            return 0;
        }

        if (rest.empty()) {
            print_usage();
            return 0;
        }

        const std::string command = rest.front();
        const std::vector<std::string> tokens(rest.begin() + 1, rest.end());

        if (globals.help || command == "help") {
            if (command == "help") {
                if (tokens.empty()) {
                    print_usage();
                    return 0;
                }
                if (!print_command_help(tokens.front())) {
                    throw UsageError("unknown command '" + tokens.front() + "'");
                }
                return 0;
            }
            if (!print_command_help(command)) throw UsageError("unknown command '" + command + "'");
            return 0;
        }

        if (command == "init") return cmd_init(globals, tokens);
        if (command == "add") return cmd_add(globals, tokens);
        if (command == "list") return cmd_list(globals, tokens);
        if (command == "search") return cmd_search(globals, tokens);
        if (command == "get") return cmd_get(globals, tokens);
        if (command == "edit") return cmd_edit(globals, tokens);
        if (command == "rm") return cmd_rm(globals, tokens);
        if (command == "gen") return cmd_gen(globals, tokens);
        if (command == "audit") return cmd_audit(globals, tokens);
        if (command == "passwd") return cmd_passwd(globals, tokens);
        if (command == "export") return cmd_export(globals, tokens);
        if (command == "import") return cmd_import(globals, tokens);
        if (command == "info") return cmd_info(globals, tokens);
        if (command == "backup") return cmd_backup(globals, tokens);
        if (command == "selftest") return cmd_selftest(globals, tokens);

        throw UsageError("unknown command '" + command + "'");
    } catch (const UsageError& error) {
        std::cerr << red("error: ") << error.what() << "\n"
                  << "Run " << bold("ciphervault --help") << " for usage.\n";
        return 2;
    } catch (const VaultError& error) {
        std::cerr << red("error: ") << error.what() << "\n";
        if (error.kind() == VaultErrorKind::Authentication) {
            std::cerr << dim("The password is case-sensitive. Caps Lock?") << "\n";
        }
        return 1;
    } catch (const std::exception& error) {
        std::cerr << red("error: ") << error.what() << "\n";
        return 1;
    }
}

}  // namespace ciphervault
