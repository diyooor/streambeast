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
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

    beast::string_view
mime_type(beast::string_view path)
{
    using beast::iequals;
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if(pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if(iequals(ext, ".htm"))  return "text/html";
    if(iequals(ext, ".html")) return "text/html";
    if(iequals(ext, ".php"))  return "text/html";
    if(iequals(ext, ".css"))  return "text/css";
    if(iequals(ext, ".txt"))  return "text/plain";
    if(iequals(ext, ".js"))   return "application/javascript";
    if(iequals(ext, ".json")) return "application/json";
    if(iequals(ext, ".xml"))  return "application/xml";
    if(iequals(ext, ".swf"))  return "application/x-shockwave-flash";
    if(iequals(ext, ".flv"))  return "video/x-flv";
    if(iequals(ext, ".png"))  return "image/png";
    if(iequals(ext, ".jpe"))  return "image/jpeg";
    if(iequals(ext, ".jpeg")) return "image/jpeg";
    if(iequals(ext, ".jpg"))  return "image/jpeg";
    if(iequals(ext, ".gif"))  return "image/gif";
    if(iequals(ext, ".bmp"))  return "image/bmp";
    if(iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
    if(iequals(ext, ".tiff")) return "image/tiff";
    if(iequals(ext, ".tif"))  return "image/tiff";
    if(iequals(ext, ".svg"))  return "image/svg+xml";
    if(iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/text";
}

    std::string
path_cat(
        beast::string_view base,
        beast::string_view path)
{
    if(base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for(auto& c : result)
        if(c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}

class ClientService {
public:
    ClientService() : resolver_(ioc_), stream_(ioc_, ctx_) {
        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(stream_.native_handle(), "example.com")) {
            boost::system::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw boost::system::system_error{ec};
        }
    }

    std::string get(const std::string& host, const std::string& port, const std::string& target, int version = 11) {
        try {
            auto const results = resolver_.resolve(host, port);
            beast::get_lowest_layer(stream_).connect(results);
            stream_.handshake(ssl::stream_base::client);

            http::request<http::string_body> req{http::verb::get, target, version};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

            http::write(stream_, req);
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(stream_, buffer, res);
            beast::error_code ec;
            stream_.shutdown(ec);
            if(ec == net::error::eof) {
                ec = {}; // Rationale: http://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ssl__stream/shutdown/overload1.html
            }
            if(ec)
                throw beast::system_error{ec};

            return beast::buffers_to_string(res.body().data());
        } catch (std::exception const& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }

private:
    net::io_context ioc_;
    ssl::context ctx_{ssl::context::sslv23_client};
    tcp::resolver resolver_;
    beast::ssl_stream<beast::tcp_stream> stream_;
};


class Application {
    public:
        Application() : client_service_(std::make_shared<ClientService>()) {}
    private:
        std::shared_ptr<ClientService> client_service_;
};

template <class Body, class Allocator>
    http::message_generator
handle_request(
        beast::string_view doc_root,
        http::request<Body, http::basic_fields<Allocator>>&& req,
        std::shared_ptr<Application const> const& app)
{
    auto const res_ = [&req](http::status status, const std::string& body, const std::string& content_type = "application/json") {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::content_type, content_type);
        res.keep_alive(req.keep_alive());
        res.body() = body;
        res.prepare_payload();
        return res;
    };

    if (req.method() == http::verb::get && req.target() == "/api/data") {
        std::string json_data = R"({
            "name": "John Doe",
            "age": 30,
            "email": "john.doe@example.com"
        })";

        // Return the JSON data as a response
        return res_(http::status::ok, json_data, "application/json");
    }

    if (req.method() == http::verb::post && req.target() == "/api/external") {
        try {
            // Parse the request body using Boost.JSON
            boost::json::value jv = boost::json::parse(req.body());

            // Extract values from JSON
            if (jv.is_object()) {
                boost::json::object& obj = jv.as_object();
                // Access JSON fields
                if (obj.contains("key")) {
                    std::string value = obj["key"].as_string().c_str();
                    std::cout << "Key value: " << value << std::endl;

                    // Formulate a response JSON
                    boost::json::object response_obj;
                    response_obj["status"] = "success";
                    response_obj["message"] = "Parsed successfully";
                    response_obj["received_value"] = value;

                    std::string response_body = boost::json::serialize(response_obj);

                    // Return a JSON response
                    return res_(http::status::ok, response_body, "application/json");
                }
            }

            return res_(http::status::bad_request, "Missing key in JSON", "application/json");
        }
        catch (const boost::system::system_error& e) {
            // Handle JSON parsing errors
            return res_(http::status::bad_request, std::string("Invalid JSON: ") + e.what(), "application/json");
        }
    }
    if( req.method() != http::verb::get &&
            req.method() != http::verb::head)
        return res_(http::status::bad_request, "Unknown HTTP-method", "text/html");
    if( req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != beast::string_view::npos)
        return res_(http::status::bad_request, "Illegal request-target", "text/html");
    std::string path = path_cat(doc_root, req.target());
    if(req.target().back() == '/')
        path.append("index.html");
    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);
    std::string msg = req.target(); 
    if(ec == beast::errc::no_such_file_or_directory)
        return res_(http::status::not_found, msg, "text/html");
    if(ec)
        return res_(http::status::internal_server_error, ec.message(), "text/html");
    auto const size = body.size();
    
    if(req.method() == http::verb::head)
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

    void
fail(beast::error_code ec, char const* what)
{
    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if(ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

class session : public std::enable_shared_from_this<session>
{
    beast::ssl_stream<beast::tcp_stream> stream_;
    beast::flat_buffer buffer_;
    std::shared_ptr<std::string const> doc_root_;
    std::shared_ptr<Application const> app_;
    http::request<http::string_body> req_;

    public:
    explicit
        session(
                tcp::socket&& socket,
                ssl::context& ctx,
                std::shared_ptr<std::string const> const& doc_root,
                std::shared_ptr<Application const> const& app)
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
            if(ec)
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

            if(ec == http::error::end_of_stream)
                return do_close();

            if(ec)
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

            if(ec)
                return fail(ec, "write");

            if(! keep_alive)
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
            if(ec)
                return fail(ec, "shutdown");

        }
};


class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;
    std::shared_ptr<Application const> app_;
    public:
    listener(
            net::io_context& ioc,
            ssl::context& ctx,
            tcp::endpoint endpoint,
            std::shared_ptr<std::string const> const& doc_root,
            std::shared_ptr<Application const> const& app)
        : ioc_(ioc)
          , ctx_(ctx)
          , acceptor_(ioc)
          , doc_root_(doc_root)
          , app_(app)
    {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        acceptor_.listen(
                net::socket_base::max_listen_connections, ec);
        if(ec)
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
            if(ec)
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


int main(int argc, char* argv[])
{
    if (argc != 5)
    {
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
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back(
                [&ioc]
                {
                ioc.run();
                });
    ioc.run();

    return EXIT_SUCCESS;
}
