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
#include <vector>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <map>
#include <sstream> // For stringstream
#include <iomanip> // For put_time
#include <curl/curl.h>
#include <string> // For std::string and std::to_string
#include <boost/beast/core/detail/base64.hpp> // For base64 encoding
#include <thread>
#include <boost/optional.hpp> // For optional values

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Adjust storage size if necessary
constexpr size_t MAX_IMAGE_STORAGE = 1000;
constexpr std::chrono::seconds IMAGE_TIMEOUT(10); // Timeout for clearing the cache

// Helper function to URL-encode a string
std::string url_encode(const std::string& value) {
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex;

    for (const auto& c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            // Any other characters are percent-encoded
            encoded << '%' << std::setw(2) << int((unsigned char)c);
        }
    }
    return encoded.str();
}

// Helper function to URL-decode a string
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

// Define Receipt structure
struct Receipt {
    std::string id;
    std::string status;
    std::string currency;
    int amount_total;
    std::string customer_name;
    std::string customer_email;
    std::string payment_status;
    std::string timestamp;

    // Construct a Receipt from JSON object
    static Receipt from_json(const boost::json::object& obj) {
        return Receipt{
            obj.at("id").as_string().c_str(),
            obj.at("status").as_string().c_str(),
            obj.at("currency").as_string().c_str(),
            static_cast<int>(obj.at("amount_total").as_int64()),
            obj.at("customer_details").as_object().at("name").as_string().c_str(),
            obj.at("customer_details").as_object().at("email").as_string().c_str(),
            obj.at("payment_status").as_string().c_str(),
            std::to_string(obj.at("created").as_int64())
        };
    }
};

// The ClientService class manages interactions with the Stripe API
class ClientService {
public:
    ClientService() {}

    // Create a checkout session
    std::string createCheckoutSession() {
        try {
            // Create a context that uses the default paths for finding CA certificates.
            ssl::context ctx{ssl::context::tlsv12_client};
            ctx.set_default_verify_paths();
            ctx.set_verify_mode(ssl::verify_peer);
            ctx.set_verify_callback([](bool preverified, ssl::verify_context& ctx) {
                char subject_name[256];
                X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
                X509_NAME_oneline(X509_get_subject_name(cert), subject_name, sizeof(subject_name));
                std::cout << "Verifying: " << subject_name << "\n";

                return preverified;
            });

            // Create an I/O context for the network operations.
            net::io_context ioc;

            // The domain name of the server.
            std::string const host = "api.stripe.com";
            std::string const port = "443";

            // Create a resolver and resolve the server address.
            tcp::resolver resolver{ioc};
            auto const results = resolver.resolve(host, port);

            // Create a socket and connect it to the server.
            beast::ssl_stream<beast::tcp_stream> stream{ioc, ctx};
            beast::get_lowest_layer(stream).connect(results);

            // Perform the SSL handshake.
            stream.handshake(ssl::stream_base::client);

            // Create URL-encoded form body
            std::string body = 
                "success_url=" + url_encode("https://sattar.xyz/success?session_id={CHECKOUT_SESSION_ID}") + // Ensure session_id is returned
                "&cancel_url=" + url_encode("https://sattar.xyz/cancel") +
                "&payment_method_types[]=" + url_encode("card") +
                "&line_items[0][price_data][currency]=" + url_encode("usd") +
                "&line_items[0][price_data][product_data][name]=" + url_encode("T-shirt") +
                "&line_items[0][price_data][unit_amount]=" + url_encode("2000") +
                "&line_items[0][quantity]=" + url_encode("1") +
                "&mode=" + url_encode("payment");

            // Set up an HTTP POST request message.
            http::request<http::string_body> req{http::verb::post, "/v1/checkout/sessions", 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            req.set(http::field::content_type, "application/x-www-form-urlencoded");
            req.set(http::field::authorization, "Bearer sk_test_51PjIZuAB0gpFN8ie2ufCaOW0HoVteth7ZcsBr3KM6XP1IFz7x7FuVAv0EF6hCJfNBSYAaPFVYYvkn3NExzktaGUc00Auhh1qpw");
            req.body() = body;
            req.prepare_payload();

            // Send the HTTP request to the remote host.
            http::write(stream, req);

            // Declare a container to hold the response.
            beast::flat_buffer buffer;
            http::response<http::string_body> res;

            // Receive the HTTP response.
            http::read(stream, buffer, res);

            // Gracefully close the stream.
            beast::error_code ec;
            stream.shutdown(ec);
            if (ec == net::error::eof || ec == ssl::error::stream_truncated) {
                ec = {};
            }
            if (ec) {
                throw beast::system_error{ec};
            }

            // Return the body of the response as a string.
            return res.body();
        } catch (const std::exception& e) {
            std::cerr << "Error in createCheckoutSession: " << e.what() << std::endl;
            return "";
        }
    }

    // Retrieve payment details and store the receipt
    std::string retrievePaymentDetails(const std::string& session_id) {
        try {
            // Setup SSL context
            ssl::context ctx{ssl::context::tlsv12_client};
            ctx.set_default_verify_paths();
            ctx.set_verify_mode(ssl::verify_peer);
            ctx.set_verify_callback([](bool preverified, ssl::verify_context& ctx) {
                    char subject_name[256];
                    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
                    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, sizeof(subject_name));
                    std::cout << "Verifying: " << subject_name << "\n";
                    return preverified;
                    });

            // I/O context and resolver setup
            net::io_context ioc;
            std::string const host = "api.stripe.com";
            std::string const port = "443";
            tcp::resolver resolver{ioc};
            auto const results = resolver.resolve(host, port);

            // Establish SSL connection
            beast::ssl_stream<beast::tcp_stream> stream{ioc, ctx};
            beast::get_lowest_layer(stream).connect(results);
            stream.handshake(ssl::stream_base::client);

            // Setup HTTP GET request for payment details
            std::string target = "/v1/checkout/sessions/" + session_id;
            http::request<http::empty_body> req{http::verb::get, target, 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            req.set(http::field::authorization, "Bearer sk_test_51PjIZuAB0gpFN8ie2ufCaOW0HoVteth7ZcsBr3KM6XP1IFz7x7FuVAv0EF6hCJfNBSYAaPFVYYvkn3NExzktaGUc00Auhh1qpw");

            // Send request and read response
            http::write(stream, req);
            beast::flat_buffer buffer;
            http::response<http::string_body> res;
            http::read(stream, buffer, res);

            // Close connection gracefully
            beast::error_code ec;
            stream.shutdown(ec);
            if (ec == net::error::eof || ec == ssl::error::stream_truncated) {
                ec = {};
            }
            if (ec) {
                throw beast::system_error{ec};
            }

            // Debug: Log the response
            std::cout << "Stripe Response: " << res.body() << std::endl;

            // Parse the payment details and store the receipt
            auto response_obj = boost::json::parse(res.body()).as_object();
            Receipt receipt = Receipt::from_json(response_obj);

            {
                std::lock_guard<std::mutex> lock(receipt_mutex_);
                receipts_.push_back(receipt);
            }

            return res.body();
        } catch (const std::exception& e) {
            std::cerr << "Error in retrievePaymentDetails: " << e.what() << std::endl;
            return "";
        }
    }

    // Retrieve a receipt by ID
    boost::optional<Receipt> getReceiptById(const std::string& id) {
        std::lock_guard<std::mutex> lock(receipt_mutex_);
        for (const auto& receipt : receipts_) {
            if (receipt.id == id) {
                return receipt;
            }
        }
        return boost::none;
    }

    // Get all stored receipts
    std::vector<Receipt> getAllReceipts() {
        std::lock_guard<std::mutex> lock(receipt_mutex_);
        return receipts_;
    }

private:
    std::vector<Receipt> receipts_;
    std::mutex receipt_mutex_;
};

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
        CameraService() : last_update_time_(std::chrono::steady_clock::now()) {
            // Start a thread to clear cache after a timeout
            cleanup_thread_ = std::thread([this]() { cleanup_cache(); });
        }

        ~CameraService() {
            stop_cleanup_thread_ = true;
            if (cleanup_thread_.joinable()) {
                cleanup_thread_.join();
            }
        }

        // Method to add an image to the storage with a timestamp
        void add_image(std::vector<unsigned char>&& image_data) {
            std::lock_guard<std::mutex> lock(storage_mutex_);
            if (image_storage_.size() >= MAX_IMAGE_STORAGE) {
                image_storage_.erase(image_storage_.begin()); // Maintain the circular buffer
            }
            auto now = std::chrono::system_clock::now();
            std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
            std::tm* now_tm = std::localtime(&now_time_t);
            std::stringstream timestamp;
            timestamp << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S");
            image_storage_[timestamp.str()] = std::move(image_data);
            image_available_ = true;
            last_update_time_ = std::chrono::steady_clock::now(); // Update the last update time
            storage_cv_.notify_all();
        }

        // Method to get the latest image for streaming
        std::vector<unsigned char> get_latest_image() {
            std::lock_guard<std::mutex> lock(storage_mutex_);
            if (!image_storage_.empty()) {
                return image_storage_.rbegin()->second; // Get the most recent image
            }
            return {};
        }

        // Method to get the image by timestamp
        std::vector<unsigned char> get_image_by_timestamp(const std::string& timestamp) {
            std::lock_guard<std::mutex> lock(storage_mutex_);
            auto it = image_storage_.find(timestamp);
            if (it != image_storage_.end()) {
                return it->second;
            }
            return {};
        }

        // Method to get a list of available timestamps
        std::vector<std::string> get_available_timestamps() {
            std::lock_guard<std::mutex> lock(storage_mutex_);
            std::vector<std::string> timestamps;
            for (const auto& entry : image_storage_) {
                timestamps.push_back(entry.first);
            }
            return timestamps;
        }

    private:
        std::map<std::string, std::vector<unsigned char>> image_storage_;
        std::mutex storage_mutex_;
        std::condition_variable storage_cv_;
        bool image_available_ = false;
        std::chrono::steady_clock::time_point last_update_time_;
        std::thread cleanup_thread_;
        bool stop_cleanup_thread_ = false;

        void cleanup_cache() {
            while (!stop_cleanup_thread_) {
                std::this_thread::sleep_for(std::chrono::seconds(1)); // Check every second
                std::lock_guard<std::mutex> lock(storage_mutex_);
                if (image_available_ &&
                        std::chrono::steady_clock::now() - last_update_time_ > IMAGE_TIMEOUT) {
                    image_storage_.clear(); // Clear the cache if the timeout is reached
                    image_available_ = false;
                }
            }
        }
};

class Application {
public:
    Application() 
        : camera_service_(std::make_shared<CameraService>()),
          client_service_(std::make_shared<ClientService>()) {}

    // Getter for CameraService
    std::shared_ptr<CameraService> get_camera_service() {
        return camera_service_;
    }

    // Handle POST image logic
    void handle_post_image(std::vector<unsigned char>&& image_data) {
        camera_service_->add_image(std::move(image_data));
    }

    // Handle GET latest image for streaming
    std::vector<unsigned char> handle_get_latest_image() {
        return camera_service_->get_latest_image();
    }

    // Handle GET image by timestamp logic
    std::vector<unsigned char> handle_get_image_by_timestamp(const std::string& timestamp) {
        return camera_service_->get_image_by_timestamp(timestamp);
    }

    // Handle GET available timestamps logic
    std::vector<std::string> handle_get_available_timestamps() {
        return camera_service_->get_available_timestamps();
    }

    // Handle creating a Stripe checkout session
    std::string handle_create_checkout_session() {
        return client_service_->createCheckoutSession();
    }

    // Handle retrieving payment details
    std::string handle_retrieve_payment_details(const std::string& session_id) {
        return client_service_->retrievePaymentDetails(session_id);
    }

    // Handle getting all stored receipts
    std::vector<Receipt> handle_get_all_receipts() {
        return client_service_->getAllReceipts();
    }

private:
    std::shared_ptr<CameraService> camera_service_;
    std::shared_ptr<ClientService> client_service_;
};

template <class Body, class Allocator>
http::message_generator handle_request(
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

    if (req.method() == http::verb::post && req.target() == "/api/create-checkout-session") {
        try {
            // Parse the JSON body
            auto json_body = boost::json::parse(req.body());
            auto items = json_body.at("items").as_array();

            // Use the parsed JSON data (e.g., to extract item details)
            for (const auto& item : items) {
                std::string id = item.at("id").as_string().c_str();
                std::string name = item.at("name").as_string().c_str();
                int price = item.at("price").as_int64();
                std::string currency = item.at("currency").as_string().c_str();
                int quantity = item.at("quantity").as_int64();

                // Debug output to verify parsing
                std::cout << "Item ID: " << id << ", Name: " << name << ", Price: " << price 
                    << ", Currency: " << currency << ", Quantity: " << quantity << std::endl;
            }

            // Use Application's method to create a checkout session
            std::string response = app->handle_create_checkout_session();

            boost::json::object response_obj;
            response_obj["status"] = "success";
            response_obj["message"] = "Checkout session created successfully";
            response_obj["response"] = boost::json::parse(response); // Parse JSON response from Stripe
            std::string response_body = boost::json::serialize(response_obj);

            return res_(http::status::ok, response_body, "application/json");
        } catch (const boost::system::system_error& e) {
            return res_(http::status::bad_request, std::string("Error parsing JSON: ") + e.what(), "application/json");
        } catch (const std::exception& e) {
            return res_(http::status::bad_request, std::string("Error creating checkout session: ") + e.what(), "application/json");
        }
    }

    // Handle GET request for real-time streaming
    if (req.method() == http::verb::get && req.target() == "/stream") {
        auto image_data = app->handle_get_latest_image();

        if (!image_data.empty()) {
            // Respond with the latest image
            http::response<http::vector_body<unsigned char>> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "image/jpeg");
            res.body() = std::move(image_data);
            res.prepare_payload();
            return res;
        }

        // No image available
        return res_(http::status::no_content, "", "application/json");
    }

    // Handle GET request for image by timestamp
    if (req.method() == http::verb::get && req.target().starts_with("/image/")) {
        // Extract the timestamp from the URI
        std::string target = std::string(req.target());
        std::string prefix = "/image/";

        // Decode the URI to handle any URL-encoded characters
        std::string timestamp_encoded = target.substr(prefix.size());
        std::string timestamp = url_decode(timestamp_encoded);

        auto image_data = app->handle_get_image_by_timestamp(timestamp);

        if (!image_data.empty()) {
            // Respond with the image
            http::response<http::vector_body<unsigned char>> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "image/jpeg");
            res.body() = std::move(image_data);
            res.prepare_payload();
            return res;
        }

        // No image was found
        return res_(http::status::not_found, "Image not found", "application/json");
    }

    // Handle GET request for available timestamps
    if (req.method() == http::verb::get && req.target() == "/timestamps") {
        auto timestamps = app->handle_get_available_timestamps();
        boost::json::array json_timestamps;

        for (const auto& timestamp : timestamps) {
            json_timestamps.emplace_back(timestamp);
        }

        boost::json::object response_obj;
        response_obj["timestamps"] = json_timestamps;
        std::string response_body = boost::json::serialize(response_obj);

        return res_(http::status::ok, response_body, "application/json");
    }

    // Handle GET request for /success endpoint
    if (req.method() == http::verb::get && req.target().starts_with("/success")) {
        std::cout << "Received success request: " << req.target() << std::endl;

        std::string target = std::string(req.target());
        std::size_t pos = target.find("session_id=");
        std::string session_id = (pos != std::string::npos) ? target.substr(pos + 11) : "";

        if (!session_id.empty()) {
            std::cout << "Session ID: " << session_id << std::endl;

            std::string payment_details = app->handle_retrieve_payment_details(session_id);

            if (payment_details.empty()) {
                return res_(http::status::internal_server_error, "Failed to retrieve payment details", "application/json");
            }

            // Parse payment details
            boost::json::object response_obj;
            try {
                response_obj = boost::json::parse(payment_details).as_object();
            } catch (const std::exception& e) {
                std::cerr << "Failed to parse payment details: " << e.what() << std::endl;
                return res_(http::status::internal_server_error, "Error parsing payment details", "application/json");
            }

            // Store payment details as a Receipt
            try {
                Receipt receipt = Receipt::from_json(response_obj);
                app->handle_retrieve_payment_details(session_id); // Store in the app
            } catch (const std::exception& e) {
                std::cerr << "Failed to store payment details: " << e.what() << std::endl;
                return res_(http::status::internal_server_error, "Error storing payment details", "application/json");
            }

            // Redirect to the home page
            http::response<http::string_body> res{http::status::see_other, req.version()};
            res.set(http::field::location, "/");
            res.keep_alive(req.keep_alive());
            return res;
        }

        return res_(http::status::bad_request, "Session ID is missing", "application/json");
    }

    // Handle GET request for cancel endpoint
    if (req.method() == http::verb::get && req.target() == "/cancel") {
        boost::json::object response_obj;
        response_obj["status"] = "cancelled";
        response_obj["message"] = "Payment was cancelled by the user";
        std::string response_body = boost::json::serialize(response_obj);

        return res_(http::status::ok, response_body, "application/json");
    }

    if (req.method() != http::verb::get &&
        req.method() != http::verb::head) {
        return res_(http::status::bad_request, "Unknown HTTP-method", "text/html");
    }

    if (req.target().empty() ||
        req.target()[0] != '/' ||
        req.target().find("..") != beast::string_view::npos) {
        return res_(http::status::bad_request, "Illegal request-target", "text/html");
    }

    std::string path = path_cat(doc_root, req.target());
    std::string target = req.target();
    if (req.target().back() == '/') {
        path.append("index.html");
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

std::string get_image_name(const std::string& target) {
    std::size_t pos = target.find_last_of('/');
    return (pos == std::string::npos) ? target : target.substr(pos + 1);
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

