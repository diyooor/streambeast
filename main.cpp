
#include <boost/json/src.hpp>
#include "server_certificate.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <map>
#include <sstream>
#include <iomanip>
#include <string>
#include <boost/beast/core/detail/base64.hpp>
#include <thread>
#include <boost/optional.hpp>
#include <unordered_map>
#include <atomic>
#include <ctime>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <boost/json.hpp>
#include <sw/redis++/redis++.h>
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Utility functions for URL encoding and decoding
std::string url_encode(const std::string& value) {
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex;

    for (const auto& c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::setw(2) << int((unsigned char)c);
        }
    }
    return encoded.str();
}

std::string url_decode(const std::string& value) {
    std::ostringstream decoded;
    for (std::size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%') {
            if (i + 2 < value.length()) {
                int hex_value;
                std::istringstream hex_stream(value.substr(i + 1, 2));
                if (hex_stream >> std::hex >> hex_value) {
                    decoded << static_cast<char>(hex_value);
                    i += 2;
                }
            }
        } else if (value[i] == '+') {
            decoded << ' ';
        } else {
            decoded << value[i];
        }
    }
    return decoded.str();
}

// Function to determine MIME type based on file extension
beast::string_view mime_type(beast::string_view path) {
    using beast::iequals;
    auto const ext = [&path] {
        auto const pos = path.rfind(".");
        if (pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if (iequals(ext, ".htm")) return "text/html";
    if (iequals(ext, ".html")) return "text/html";
    if (iequals(ext, ".php")) return "text/html";
    if (iequals(ext, ".css")) return "text/css";
    if (iequals(ext, ".txt")) return "text/plain";
    if (iequals(ext, ".js")) return "application/javascript";
    if (iequals(ext, ".json")) return "application/json";
    if (iequals(ext, ".xml")) return "application/xml";
    if (iequals(ext, ".swf")) return "application/x-shockwave-flash";
    if (iequals(ext, ".flv")) return "video/x-flv";
    if (iequals(ext, ".png")) return "image/png";
    if (iequals(ext, ".jpe")) return "image/jpeg";
    if (iequals(ext, ".jpeg")) return "image/jpeg";
    if (iequals(ext, ".jpg")) return "image/jpeg";
    if (iequals(ext, ".gif")) return "image/gif";
    if (iequals(ext, ".bmp")) return "image/bmp";
    if (iequals(ext, ".ico")) return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff")) return "image/tiff";
    if (iequals(ext, ".tif")) return "image/tiff";
    if (iequals(ext, ".svg")) return "image/svg+xml";
    if (iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/text";
}

// Function to concatenate base path with relative path
std::string path_cat(beast::string_view base, beast::string_view path) {
    if (base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if (result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for (auto& c : result)
        if (c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if (result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}

// SystemService class to track server status
class SystemService {
    public:
        SystemService() : start_time_(std::chrono::steady_clock::now()), request_count_(0) {}

        void increment_request_count() {
            std::lock_guard<std::mutex> lock(mutex_);
            ++request_count_;
        }

        boost::json::object get_status() const {
            std::lock_guard<std::mutex> lock(mutex_);
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_time_).count();

            boost::json::object status;
            status["uptime"] = uptime;
            status["request_count"] = request_count_;

            // Add memory usage
            struct sysinfo memInfo;
            sysinfo(&memInfo);
            status["total_memory"] = memInfo.totalram * memInfo.mem_unit / (1024 * 1024); // in MB
            status["free_memory"] = memInfo.freeram * memInfo.mem_unit / (1024 * 1024); // in MB

            // Add disk space
            struct statvfs diskInfo;
            statvfs("/", &diskInfo);
            unsigned long totalDisk = diskInfo.f_blocks * diskInfo.f_frsize;
            unsigned long freeDisk = diskInfo.f_bfree * diskInfo.f_frsize;
            status["total_disk"] = totalDisk / (1024 * 1024); // in MB
            status["free_disk"] = freeDisk / (1024 * 1024); // in MB

            return status;
        }

    private:
        std::chrono::steady_clock::time_point start_time_;
        mutable std::mutex mutex_;
        std::size_t request_count_;
};

// Application class to hold application services
class Application {
    public:
        Application() : system_service_(std::make_shared<SystemService>()) {}

        std::shared_ptr<SystemService> get_system_service() { return system_service_; }

    private:
        std::shared_ptr<SystemService> system_service_;
};

// Function to handle GET requests
template <class Body, class Allocator>
http::message_generator handle_get_request(
        beast::string_view doc_root,
        http::request<Body, http::basic_fields<Allocator>>&& req,
        std::shared_ptr<Application> app) {

    auto const res_ = [&req](http::status status, const std::string& body, const std::string& content_type = "application/json") {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::content_type, content_type);
        res.keep_alive(req.keep_alive());
        res.body() = body;
        res.prepare_payload();
        return res;
    };

    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != beast::string_view::npos) {
        return res_(http::status::bad_request, "Illegal request-target", "text/html");
    }

    std::string target = req.target();
    if (target == "/status") {
        auto system_service = app->get_system_service();
        auto status = system_service->get_status();
        auto body = boost::json::serialize(status);
        return res_(http::status::ok, body, "application/json");
    }

    std::string path = path_cat(doc_root, req.target());
    if (req.target().back() == '/') {
        path.append("index2.html");
    }
    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);
    std::string msg = req.target();
    if (ec == beast::errc::no_such_file_or_directory) {
        return res_(http::status::not_found, msg, "text/html");
    }
    if (ec) {
        return res_(http::status::internal_server_error, ec.message(), "text/html");
    }

    auto const size = body.size();

    if (req.method() == http::verb::head) {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, mime_type(path));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return res;
    }

    http::response<http::file_body> res{
        std::piecewise_construct,
            std::make_tuple(std::move(body)),
            std::make_tuple(http::status::ok, req.version())};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    res.keep_alive(req.keep_alive());
    return res;
}

// Function to handle POST requests
template <class Body, class Allocator>
http::message_generator handle_post_request(
        beast::string_view doc_root,
        http::request<Body, http::basic_fields<Allocator>>&& req,
        std::shared_ptr<Application> app) {

    auto const res_ = [&req](http::status status, const std::string& body, const std::string& content_type = "application/json") {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::content_type, content_type);
        res.keep_alive(req.keep_alive());
        res.body() = body;
        res.prepare_payload();
        return res;
    };

    if (req.target() == "") {
        // Parse the request body
        boost::json::value parsed_body = boost::json::parse(req.body());
        boost::json::object result;
        // Add logic here for processing the POST data
        if (parsed_body.is_object()) {
            boost::json::object obj = parsed_body.as_object();
            // Check specific conditions and modify the response accordingly
            if (obj.contains("action") && obj["action"].as_string() == "update") {
                result["message"] = "Update successful";
            } else {
                result["message"] = "Invalid action";
            }
        }
        auto body = boost::json::serialize(result);
        return res_(http::status::ok, body, "application/json");
    }

    return res_(http::status::not_found, "Endpoint not found", "application/json");
}

template <class Body, class Allocator>
http::message_generator handle_request(
        beast::string_view doc_root,
        http::request<Body, http::basic_fields<Allocator>>&& req,
        std::shared_ptr<Application> app) {

    if (req.method() == http::verb::get || req.method() == http::verb::head) {
        return handle_get_request(doc_root, std::move(req), app);
    }
    else if (req.method() == http::verb::post) {
        return handle_post_request(doc_root, std::move(req), app);
    }
    else {
        // Method not allowed
        http::response<http::string_body> res{http::status::method_not_allowed, req.version()};
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "Method not allowed";
        res.prepare_payload();
        return res;
    }
}

void fail(beast::error_code ec, char const* what) {
    if (ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

// Session class to manage client-server interactions
class session : public std::enable_shared_from_this<session> {
    beast::ssl_stream<beast::tcp_stream> stream_;
    beast::flat_buffer buffer_;
    std::shared_ptr<std::string const> doc_root_;
    std::shared_ptr<Application> app_;
    http::request<http::string_body> req_;

    public:
    explicit session(
            tcp::socket&& socket,
            ssl::context& ctx,
            std::shared_ptr<std::string const> const& doc_root,
            std::shared_ptr<Application> app)
        : stream_(std::move(socket), ctx), doc_root_(doc_root), app_(app)
    {
    }

    void run() {
        net::dispatch(
                stream_.get_executor(),
                beast::bind_front_handler(
                    &session::on_run,
                    shared_from_this()));
    }

    void on_run() {
        beast::get_lowest_layer(stream_).expires_after(
                std::chrono::seconds(30));

        stream_.async_handshake(
                ssl::stream_base::server,
                beast::bind_front_handler(
                    &session::on_handshake,
                    shared_from_this()));
    }

    void on_handshake(beast::error_code ec) {
        if (ec)
            return fail(ec, "handshake");

        do_read();
    }

    void do_read() {
        req_ = {};

        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        http::async_read(stream_, buffer_, req_,
                beast::bind_front_handler(
                    &session::on_read,
                    shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec == http::error::end_of_stream)
            return do_close();

        if (ec)
            return fail(ec, "read");

        app_->get_system_service()->increment_request_count();

        send_response(
                handle_request(*doc_root_, std::move(req_), app_));
    }

    void send_response(http::message_generator&& msg) {
        bool keep_alive = msg.keep_alive();

        beast::async_write(
                stream_,
                std::move(msg),
                beast::bind_front_handler(
                    &session::on_write,
                    this->shared_from_this(),
                    keep_alive));
    }

    void on_write(bool keep_alive, beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        if (!keep_alive) {
            return do_close();
        }

        do_read();
    }

    void do_close() {
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        stream_.async_shutdown(
                beast::bind_front_handler(
                    &session::on_shutdown,
                    shared_from_this()));
    }

    void on_shutdown(beast::error_code ec) {
        if (ec)
            return fail(ec, "shutdown");
    }
};

// Listener class to accept incoming connections
class listener : public std::enable_shared_from_this<listener> {
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;
    std::shared_ptr<Application> app_;

    public:
    listener(
            net::io_context& ioc,
            ssl::context& ctx,
            tcp::endpoint endpoint,
            std::shared_ptr<std::string const> const& doc_root,
            std::shared_ptr<Application> app)
        : ioc_(ioc), ctx_(ctx), acceptor_(ioc), doc_root_(doc_root), app_(app)
    {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            fail(ec, "open");
            return;
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            fail(ec, "set_option");
            return;
        }

        acceptor_.bind(endpoint, ec);
        if (ec) {
            fail(ec, "bind");
            return;
        }

        acceptor_.listen(
                net::socket_base::max_listen_connections, ec);
        if (ec) {
            fail(ec, "listen");
            return;
        }
    }

    void run() {
        do_accept();
    }

    private:
    void do_accept() {
        acceptor_.async_accept(
                net::make_strand(ioc_),
                beast::bind_front_handler(
                    &listener::on_accept,
                    shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }
        else {
            std::make_shared<session>(
                    std::move(socket),
                    ctx_,
                    doc_root_,
                    app_)->run();
        }

        do_accept();
    }
};

// Main function to initialize and run the server
int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr <<
            "Usage: http-server-async-ssl <address> <port> <doc_root> <threads>\n" <<
            "Example:\n" <<
            "    http-server-async-ssl 0.0.0.0 8080 . 1\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const doc_root = std::make_shared<std::string>(argv[3]);
    auto const threads = std::max<int>(1, std::atoi(argv[4]));
    auto const app = std::make_shared<Application>();
    net::io_context ioc{threads};

    ssl::context ctx{ssl::context::tlsv12};

    load_server_certificate(ctx);

    std::make_shared<listener>(
            ioc,
            ctx,
            tcp::endpoint{address, port},
            doc_root,
            app)->run();

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back(
                [&ioc] {
                ioc.run();
                });
    ioc.run();

    return EXIT_SUCCESS;
}

