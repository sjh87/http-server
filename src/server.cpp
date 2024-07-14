#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <queue>
#include <regex>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <semaphore>
#include <sys/stat.h>
#include <thread>
#include <zlib.h>

#define CONNECTION_BACKLOG_QUEUE_MAX 10
#define PORT 4221
#define REQUEST_SIZE 2048
#define SYSTEM_CORE_COUNT 12
#define MAX_CONNECTION_QUEUE_SIZE SYSTEM_CORE_COUNT * 3

std::atomic<bool> running(true);
int server_fd;

#include <vector>
#include <string>
#include <zlib.h>

// I had to steal this and mess with it to deal with small inputs well
std::vector<char> gzip_compress(const std::string& data) {
    std::vector<char> compressed;
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     31, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("deflateInit2 failed");
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());

    int ret;
    do {
        size_t prev_size = compressed.size();
        compressed.resize(prev_size + 32768);

        zs.next_out = reinterpret_cast<Bytef*>(compressed.data() + prev_size);
        zs.avail_out = static_cast<uInt>(compressed.size() - prev_size);

        ret = deflate(&zs, Z_FINISH);

        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&zs);
            throw std::runtime_error("deflate failed");
        }
    } while (ret != Z_STREAM_END);

    compressed.resize(zs.total_out);
    deflateEnd(&zs);

    return compressed;
}

class HTTPHeaders {
  std::map<std::string, std::string> headerMap;

  public:

    HTTPHeaders() = default;

    HTTPHeaders(std::initializer_list<std::pair<const std::string, std::string>> init) {
      headerMap = init;
    }

    void add(const std::string key, const std::string value) {
      headerMap[key] = value;
    }

    void add(const std::string key, int value) {
      headerMap[key] = std::to_string(value);
    }

    std::string toString() const {
      std::string headerStr;

      for (auto [key, value]:headerMap) {
        headerStr += key + ": " + value + "\r\n";
      }

      return headerStr;
    }

    std::string getHeader(const std::string &key) const {
      auto it = headerMap.find(key);
      if (it != headerMap.end())
      {
        return it->second;
      }
      return "";
    }
};

class HTTPStatus {
private:
    std::string message;
    std::string protocol = "HTTP/1.1";
    unsigned value = 200;

public:
    HTTPStatus() = default;

    explicit HTTPStatus(unsigned v) {
        switch (v) {
            case 201:
                message = "Created";
                value = 201;
                break;
            case 400:
                message = "Bad Request";
                value = 400;
                break;
            case 404:
                message = "Not Found";
                value = 404;
                break;
            case 500:
                message = "Internal Server Error";
                value = 500;
                break;
            default:
                message = "OK";
                value = 200;
                break;
        }
    }

    std::string toString() const {
        return protocol + " " + std::to_string(value) + " " + message;
    }
};

class HTTPBody {
  std::vector<char> buffer;

public:
    HTTPBody() = default;

    HTTPBody(const std::string& v) : buffer(v.begin(), v.end()) {}

    HTTPBody(const std::vector<char>& v) : buffer(v) {}

    HTTPBody(const char* v, size_t length) : buffer(v, v + length) {}

    ~HTTPBody() = default;

    std::string toString() const {
        return std::string(buffer.begin(), buffer.end());
    }
};

class HTTPResponse {
private:
    HTTPStatus status;
    HTTPHeaders headers;
    HTTPBody body;

public:
    HTTPResponse(unsigned s)
        : status(s) {}

    HTTPResponse(HTTPStatus s)
        : status(s) {}

    HTTPResponse(HTTPStatus s, HTTPBody b)
        : status(s), body(b) {}

    HTTPResponse(unsigned s, HTTPBody b)
        : status(s), body(b) {}

    HTTPResponse(HTTPStatus s, HTTPHeaders h)
        : status(s), headers(h) {}

    HTTPResponse(unsigned s, HTTPHeaders h)
        : status(s), headers(h) {}

    HTTPResponse(HTTPStatus s, HTTPHeaders h, HTTPBody b)
        : status(s), headers(h), body(b) {}

    HTTPResponse(unsigned s, HTTPHeaders h, std::string b)
        : status(s), headers(h), body(b) {}

    HTTPResponse(HTTPStatus s, HTTPHeaders h, std::string b)
        : status(s), headers(h), body(b) {}

    std::string toString() const {
        std::string output;

        output += status.toString() + "\r\n";

        std::string headersString = headers.toString();
        if (!headersString.empty()) {
            output += headersString;
        }

        output += "\r\n";

        std::string bodyString = body.toString();
        if (!bodyString.empty()) {
            output += bodyString;
        }

        return output;
    }
};

// remove leading and trailing whitespace from string in place
void static trimInPlace(std::string &s) {
  std::string::iterator c;

  c = s.begin();
  while (*(c++) == ' ')
    s = s.substr(1);

  c = s.end();
  while (*(c--) == ' ')
    s = s.substr(0, s.size());
}

class HTTPRequest {
  HTTPHeaders headers;
  HTTPBody body;
  std::string path;

  void parseHeaders(std::string req) {
    std::size_t startOfHeaderSection = req.find_first_of("\r\n") + 2;
    std::size_t endOfHeaderSection = req.find_last_of("\r\n");
    std::string headerSection =
      req.substr(startOfHeaderSection, endOfHeaderSection);

    std::string key;
    std::string value;

    while (headerSection.size()) {
      std::size_t endOfHeader = headerSection.find_first_of("\r\n");
      std::size_t endOfKey = headerSection.find_first_of(":");

      if (endOfKey == -1) return;

      key = headerSection.substr(0, endOfKey);
      value = headerSection.substr(endOfKey + 1, (endOfHeader - endOfKey) - 1);

      trimInPlace(key);
      trimInPlace(value);

      headers.add(key, value);

      headerSection = headerSection.substr(endOfHeader + 2);
    }
  }

  public:
    HTTPRequest(std::string req) {
      std::string route = req.substr(0, req.find("\r\n"));

      parseHeaders(req);
      std::string p = route.substr(0, route.find_last_of(" "));
      path = p;

      std::string b = req.substr(req.find_last_of("\r\n") + 1);
      body = HTTPBody(b);
    }

    std::string getPath() const {
      return path;
    }

    HTTPHeaders getHeaders() const {
      return headers;
    }

    HTTPBody getBody() const {
      return body;
    }
};

std::string directory;

const std::regex POST_FILE("POST /files/[^/]*");
const std::regex GET_FILE("GET /files/[^/]*");
const std::string GET_ROOT = "GET /";
const std::string GET_USER_AGENT = "GET /user-agent";
const std::regex GET_ECHO("GET /echo/[^/]*");

HTTPResponse handlePostFile(const HTTPRequest& request) {
    if (directory.empty()) {
        return HTTPResponse(500);
    }

    const HTTPHeaders headers = request.getHeaders();
    if (headers.getHeader("Content-Type") != "application/octet-stream" ||
        std::stoi(headers.getHeader("Content-Length")) != request.getBody().toString().size())
      return HTTPResponse(400);


    const std::string filename = request.getPath().substr(request.getPath().find_last_of("/") + 1);

    if (filename.empty() || request.getBody().toString().empty())
        return HTTPResponse(400);

    const std::string fullPath = directory + "/" + filename;

    std::ofstream file(fullPath);
    if (file.fail())
        return HTTPResponse(500);

    file << request.getBody().toString();
    file.close();

    return HTTPResponse(201);
}

HTTPResponse handleGetFile(const std::string& path) {
    const std::string filename = path.substr(path.find_last_of("/") + 1);
    const std::string fullPath = directory + "/" + filename;

    std::ifstream file(fullPath);
    if (file.fail()) {
        return HTTPResponse(404);
    }

    std::string fileContents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return HTTPResponse(200U, HTTPHeaders({
        {"Content-Type", "application/octet-stream"},
        {"Content-Length", std::to_string(fileContents.size())}
    }), fileContents);
}

HTTPResponse handleUserAgent(const HTTPRequest& request) {
    const std::string userAgent = request.getHeaders().getHeader("User-Agent");
    return HTTPResponse(200, HTTPHeaders({
        {"Content-Type", "text/plain"},
        {"Content-Length", std::to_string(userAgent.size())}
    }), userAgent);
}

HTTPResponse handleEcho(const HTTPRequest& request) {
    const std::string message = request.getPath().substr(request.getPath().find_last_of("/") + 1);
    HTTPHeaders headers = HTTPHeaders({
        {"Content-Type", "text/plain"}
    });

    std::string responseBody;

    if (request.getHeaders().getHeader("Accept-Encoding").contains("gzip")) {
        headers.add("Content-Encoding", "gzip");
        std::vector<char> compressedBytes = gzip_compress(message);
        responseBody = std::string(compressedBytes.begin(), compressedBytes.end());
    } else {
        responseBody = message;
    }

    headers.add("Content-Length", std::to_string(responseBody.size()));

    return HTTPResponse(200, headers, responseBody);
}

HTTPResponse handleRoot() {
    return HTTPResponse(200, HTTPHeaders({{"Content-Length", "0"}}));
}

HTTPResponse handleNotFound() {
    return HTTPResponse(404, HTTPHeaders({
        {"Content-Type", "text/plain"},
        {"Content-Length", "9"}
    }), "Not Found");
}

HTTPResponse respond(HTTPRequest request) {
    const std::string path = request.getPath();

    if (std::regex_match(path, POST_FILE)) {
        return handlePostFile(request); 
    }

    if (std::regex_match(path, GET_FILE)) {
        return handleGetFile(path);
    }

    if (path == GET_USER_AGENT) {
        return handleUserAgent(request);
    }

    if (std::regex_match(path, GET_ECHO)) {
        return handleEcho(request);
    }

    if (path == GET_ROOT) {
        return handleRoot();
    }

    return handleNotFound();
}

class ConnectionQueue {
  // 
  std::counting_semaphore<MAX_CONNECTION_QUEUE_SIZE> s =
    std::counting_semaphore<MAX_CONNECTION_QUEUE_SIZE>(0);
  std::mutex m;
  std::queue<int> q;

  public:
    void push(int socket_desc) {
      std::lock_guard<std::mutex> lock(m);

      q.push(socket_desc);

      s.release();
    }

    int pop() {
        while (running.load(std::memory_order_acquire)) {
            if (s.try_acquire_for(std::chrono::milliseconds(100))) {
                std::lock_guard<std::mutex> lock(m);
                if (!q.empty()) {
                    int d = q.front();
                    q.pop();
                    return d;
                }
            }
        }
        return -1; // not a valid fd, so signals the thread to stop waiting
    }
};

std::vector<std::thread> threadPool(SYSTEM_CORE_COUNT);

void closeServerHandler(int signal) {
  std::cout << " Shutting down!" << std::endl;
  running.store(false);

  for (auto &thread:threadPool) {
    while (true) {
      if (thread.joinable()) {
        thread.join();
        break;
      }
    }
  }

  if (server_fd > -1)
    close(server_fd);

  exit(EXIT_SUCCESS);
}

void handleRequest(int socket_desc) {
  char req[REQUEST_SIZE] = { '\0' };
  ssize_t bytes_read = read(socket_desc, req, REQUEST_SIZE - 1);

  if (bytes_read == -1) {
    std::cout << "error when reading request!\n";
    return;
  }

  HTTPRequest request = HTTPRequest(std::string(req));

  HTTPResponse response = respond(request);

  std::string responseStr = response.toString();
  std::vector<char> v(responseStr.begin(), responseStr.end());

  send(socket_desc, v.data(), responseStr.size(), 0);
}

void ingestFromQueue(ConnectionQueue *q) {
  while (true) {
    int socket_desc = q->pop();
    if (socket_desc == -1)
      break;

    handleRequest(socket_desc);

    close(socket_desc);
  }
}

int main(int argc, char **argv) {
  signal (SIGINT, closeServerHandler);

  if (argc > 2) {
    std::string arg1 = std::string(argv[1]);
    std::string arg2 = std::string(argv[2]);
    if (arg1 == "--directory") {
      struct stat sb;
      if (stat(arg2.data(), &sb)) {
        std::cout << "directory " << arg2 << " does not exist!" << std::endl;
        exit(1);
      }
      directory = arg2;
    }
  }

  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return EXIT_FAILURE;
  }

  // prevents 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed to configure server socket\n";
    return EXIT_FAILURE;
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port " << PORT << std::endl;
    return EXIT_FAILURE;
  }

  if (listen(server_fd, CONNECTION_BACKLOG_QUEUE_MAX)) {
    std::cerr << "listen failed" << std::endl;
    return EXIT_FAILURE;
  }

  ConnectionQueue q = ConnectionQueue();

  for (auto &thread:threadPool)
    thread = std::thread(ingestFromQueue, &q);

  std::cout << "Server started! Waiting on port " << PORT << std::endl;
  while (running.load()) {
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    int socket_desc = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
    std::cout << "Client connected from " << inet_ntoa(client_addr.sin_addr) << std::endl;
    q.push(socket_desc);
  }

  return EXIT_SUCCESS;
}
