#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include "server_certificate.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <chrono>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Adjust storage size if necessary
constexpr size_t MAX_IMAGE_STORAGE = 1000;

// Global vector to store images
std::vector<std::vector<unsigned char>> image_storage;
std::mutex storage_mutex;
std::condition_variable storage_cv;
bool image_available = false;

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

class CameraService {
    public:
        CameraService() = default;

        // Method to add an image to the storage
        void add_image(std::vector<unsigned char>&& image_data) {
            std::lock_guard<std::mutex> lock(storage_mutex_);
            if (image_storage_.size() >= MAX_IMAGE_STORAGE) {
                image_storage_.erase(image_storage_.begin()); // Maintain the circular buffer
            }
            image_storage_.emplace_back(std::move(image_data));
            image_available_ = true;
            storage_cv_.notify_all();
        }

        // Method to get the latest image from the storage
        std::vector<unsigned char> get_latest_image() {
            std::unique_lock<std::mutex> lock(storage_mutex_);
            if (storage_cv_.wait_for(lock, std::chrono::seconds(1), [this] { return image_available_; })) {
                if (!image_storage_.empty()) {
                    return image_storage_.back(); // Always use the most recent image
                }
            }
            return {};
        }

    private:
        std::vector<std::vector<unsigned char>> image_storage_;
        std::mutex storage_mutex_;
        std::condition_variable storage_cv_;
        bool image_available_ = false;
};

class Application {
    public:
        Application() : camera_service_(std::make_shared<CameraService>()) {}

        // Getter for CameraService
        std::shared_ptr<CameraService> get_camera_service() {
            return camera_service_;
        }

        // Handle POST image logic
        void handle_post_image(std::vector<unsigned char>&& image_data) {
            camera_service_->add_image(std::move(image_data));
        }

        // Handle GET stream logic
        std::vector<unsigned char> handle_get_stream() {
            return camera_service_->get_latest_image();
        }

    private:
        std::shared_ptr<CameraService> camera_service_;
};

template <class Body, class Allocator>
http::message_generator handle_request(
        beast::string_view doc_root,
        http::request<Body, http::basic_fields<Allocator>>&& req,
        std::shared_ptr<Application> app)
{
    auto const res_ = [&req](http::status status, const std::string& body, const std::string& content_type = "application/json") {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::content_type, content_type);
        res.keep_alive(req.keep_alive());
        res.body() = body;
        res.prepare_payload();
        return res;
    };

    if (req.method() == http::verb::post && req.target() == "/api/external") {
        try {
            // Extract the image from the request body
            std::vector<unsigned char> image_data(req.body().begin(), req.body().end());

            // Store the image using the application instance
            app->handle_post_image(std::move(image_data));

            boost::json::object response_obj;
            response_obj["status"] = "success";
            response_obj["message"] = "Image uploaded successfully";
            std::string response_body = boost::json::serialize(response_obj);

            return res_(http::status::ok, response_body, "application/json");
        } catch (const std::exception& e) {
            return res_(http::status::bad_request, std::string("Error uploading image: ") + e.what(), "application/json");
        }
    }

    if (req.method() == http::verb::get && req.target() == "/stream") {
        std::vector<unsigned char> image_data = app->handle_get_stream();

        if (!image_data.empty()) {
            // Respond with the image
            http::response<http::vector_body<unsigned char>> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "image/jpeg");
            res.body() = std::move(image_data);
            res.prepare_payload();
            return res;
        }

        // No image was available
        return res_(http::status::no_content, "", "application/json");
    }

    if (req.method() != http::verb::get &&
            req.method() != http::verb::head)
        return res_(http::status::bad_request, "Unknown HTTP-method", "text/html");

    if (req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != beast::string_view::npos)
        return res_(http::status::bad_request, "Illegal request-target", "text/html");

    std::string path = path_cat(doc_root, req.target());
    if (req.target().back() == '/')
        path.append("index.html");

    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);
    std::string msg = req.target();
    if (ec == beast::errc::no_such_file_or_directory)
        return res_(http::status::not_found, msg, "text/html");
    if (ec)
        return res_(http::status::internal_server_error, ec.message(), "text/html");

    auto const size = body.size();

    if (req.method() == http::verb::head)
    {
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

void fail(beast::error_code ec, char const* what) {
    if (ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

class session : public std::enable_shared_from_this<session> {
    beast::ssl_stream<beast::tcp_stream> stream_;
    beast::flat_buffer buffer_;
    std::shared_ptr<std::string const> doc_root_;
    std::shared_ptr<Application> app_;
    http::request<http::string_body> req_;

    public:
    explicit
        session(
                tcp::socket&& socket,
                ssl::context& ctx,
                std::shared_ptr<std::string const> const& doc_root,
                std::shared_ptr<Application> app)
        : stream_(std::move(socket), ctx)
          , doc_root_(doc_root), app_(app)
    {
    }

    void
        run()
        {
            net::dispatch(
                    stream_.get_executor(),
                    beast::bind_front_handler(
                        &session::on_run,
                        shared_from_this()));
        }

    void
        on_run()
        {
            beast::get_lowest_layer(stream_).expires_after(
                    std::chrono::seconds(30));

            stream_.async_handshake(
                    ssl::stream_base::server,
                    beast::bind_front_handler(
                        &session::on_handshake,
                        shared_from_this()));
        }

    void
        on_handshake(beast::error_code ec)
        {
            if (ec)
                return fail(ec, "handshake");

            do_read();
        }

    void
        do_read()
        {

            req_ = {};

            beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

            http::async_read(stream_, buffer_, req_,
                    beast::bind_front_handler(
                        &session::on_read,
                        shared_from_this()));
        }

    void
        on_read(
                beast::error_code ec,
                std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);

            if (ec == http::error::end_of_stream)
                return do_close();

            if (ec)
                return fail(ec, "read");

            send_response(
                    handle_request(*doc_root_, std::move(req_), app_));
        }

    void
        send_response(http::message_generator&& msg)
        {
            bool keep_alive = msg.keep_alive();

            beast::async_write(
                    stream_,
                    std::move(msg),
                    beast::bind_front_handler(
                        &session::on_write,
                        this->shared_from_this(),
                        keep_alive));
        }

    void
        on_write(
                bool keep_alive,
                beast::error_code ec,
                std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);

            if (ec)
                return fail(ec, "write");

            if (!keep_alive)
            {

                return do_close();
            }

            do_read();
        }

    void
        do_close()
        {
            beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

            stream_.async_shutdown(
                    beast::bind_front_handler(
                        &session::on_shutdown,
                        shared_from_this()));
        }

    void
        on_shutdown(beast::error_code ec)
        {
            if (ec)
                return fail(ec, "shutdown");

        }
};

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
        : ioc_(ioc)
          , ctx_(ctx)
          , acceptor_(ioc)
          , doc_root_(doc_root)
          , app_(app)
    {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec)
        {
            fail(ec, "open");
            return;
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
        {
            fail(ec, "set_option");
            return;
        }

        acceptor_.bind(endpoint, ec);
        if (ec)
        {
            fail(ec, "bind");
            return;
        }

        acceptor_.listen(
                net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    void
        run()
        {
            do_accept();
        }

    private:
    void
        do_accept()
        {
            acceptor_.async_accept(
                    net::make_strand(ioc_),
                    beast::bind_front_handler(
                        &listener::on_accept,
                        shared_from_this()));
        }

    void
        on_accept(beast::error_code ec, tcp::socket socket)
        {
            if (ec)
            {
                fail(ec, "accept");
                return; // To avoid infinite loop
            }
            else
            {
                std::make_shared<session>(
                        std::move(socket),
                        ctx_,
                        doc_root_,
                        app_)->run();
            }

            do_accept();
        }
};

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
                [&ioc]
                {
                ioc.run();
                });
    ioc.run();

    return EXIT_SUCCESS;
}

