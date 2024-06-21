#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
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
#include <thread>

#define HTTP_200 "HTTP/1.1 200 OK\r\n"
#define HTTP_404 "HTTP/1.1 404 Not Found\r\n"
#define REQUEST_SIZE 2048

bool running = true;
int server_fd;

class HTTPHeaders {
  std::map<std::string, std::string> headerMap;

  public:

    HTTPHeaders() {
    }

    HTTPHeaders(std::map<std::string, std::string> map) {
      headerMap = map;
    }

    void add(std::string key, std::string value) {
      headerMap[key] = value;
    }

    void add(std::string key, int value) {
      headerMap[key] = std::to_string(value);
    }

    std::string toString() {
      std::string headerStr;

      for (auto [key, value]:headerMap) {
        headerStr += key + ": " + value + "\r\n";
      }

      return headerStr;
    }

    std::string getHeader(std::string k) {
      return headerMap[k];
    }
};

class HTTPStatus {
  std::string message;
  std::string protocol = "HTTP/1.1";
  unsigned value = 200;

  public:
    HTTPStatus(unsigned v)
    {
      switch (v)
      {
      case 404:
        message = "Not Found";
        value = 404;

        break;

      default:
        message = "OK";
        value = 200;

        break;
      }
    }

    HTTPStatus() {}

    std::string toString() {
      std::string statusString = "";

      statusString += protocol + " " + std::to_string(value) + " " + message;

      return statusString;
    }
};

class HTTPBody {
  std::string value;

  public:

    HTTPBody(std::string v) {
      value = v;
    }

    HTTPBody() {
      value = "";
    }

    std::string toString() {
      return value;
    }
};

class HTTPResponse {
  HTTPStatus status;
  HTTPHeaders headers;
  HTTPBody body;

  public:

    HTTPResponse(HTTPStatus s, HTTPBody b) {
      status = s;
      body = b;
    }

    HTTPResponse(HTTPStatus s) {
      status = s;
    }


    HTTPResponse(HTTPStatus s, HTTPHeaders h) {
      status = s;
      headers = h;
    }

    HTTPResponse(HTTPStatus s, HTTPHeaders h, HTTPBody b) {
      status = s;
      headers = h;
      body = b;
    }

    std::string toString() {
      std::string output;

      output += status.toString() + "\r\n";

      if (headers.toString().size()) output += headers.toString();

      output += "\r\n";

      if (body.toString().size()) output += body.toString();

      return output;
    }
};

class HTTPRequest {
  HTTPHeaders headers;
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
      value = headerSection.substr(endOfKey + 2, (endOfHeader - endOfKey) - 2);

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
    }

    std::string getPath() {
      return path;
    }

    HTTPHeaders getHeaders() {
      return headers;
    }
};

HTTPResponse respond(HTTPRequest request) {
    std::string path = request.getPath();

    std::string getUserAgent = "GET /user-agent";
    if (getUserAgent == path) {

      std::string userAgent = request.getHeaders().getHeader("User-Agent");
      HTTPHeaders headers = HTTPHeaders();
      headers.add("Content-Type", "text/plain");
      headers.add("Content-Length", userAgent.size());

      HTTPBody body = HTTPBody(userAgent);

      return HTTPResponse(200, headers, body);
    }

    std::regex getEcho("GET /echo/[^/]*");
    if (std::regex_match(path, getEcho)) {
      std::string message = path.substr(path.find_last_of("/") + 1);

      HTTPHeaders headers = HTTPHeaders();
      headers.add("Content-Type", "text/plain");
      headers.add("Content-Length", message.size());

      HTTPBody body = HTTPBody(message);

      return HTTPResponse(200);
    }

    std::string getRoot = "GET /";
    if (getRoot == path) return HTTPResponse(200);

    HTTPHeaders headers = HTTPHeaders({
      {"Content-Type", "text/plain"},
      {"Content-Length", "9"}
    });

    return HTTPResponse(404, headers, HTTPBody("Not Found"));
}

class ConnectionQueue {
  std::binary_semaphore s = std::binary_semaphore(0);
  std::mutex m;
  std::queue<int> q;

  public:
    void push(int socket_desc) {
      std::lock_guard<std::mutex> lock(m);

      q.push(socket_desc);

      s.release();
    }

    int pop() {
      s.acquire();
      std::lock_guard<std::mutex> lock(m);

      int d;

      d = q.front();

      q.pop();

      return d;
    }
};

void closeServerHandler(int signal) {
  std::cout << " Shutting down!" << std::endl;
  close(server_fd);
  exit(EXIT_SUCCESS);
}

void handleRequest(int socket_desc) {
  char req[REQUEST_SIZE] = { '\0' };
  ssize_t bytes_read = read(socket_desc, req, REQUEST_SIZE - 1);
  std::cout << "Client connected\n";

  if (bytes_read == -1) {
    std::cout << "error when reading request!\n";
    return;
  }

  HTTPRequest request = HTTPRequest(std::string(req));

  HTTPResponse response = respond(request);

  std::string responseStr = response.toString();

  send(socket_desc, responseStr.data(), responseStr.size(), 0);
}

void injestFromQueue(ConnectionQueue *q) {
  while (true) {
    int socket_desc = q->pop();
    handleRequest(socket_desc);
    close(socket_desc);
  }
}

int main(int argc, char **argv) {
  signal (SIGINT, closeServerHandler);

  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return EXIT_FAILURE;
  }

  // prevents 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return EXIT_FAILURE;
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);

  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return EXIT_FAILURE;
  }

  int connection_backlog = 10;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return EXIT_FAILURE;
  }

  ConnectionQueue *q = new ConnectionQueue();

  std::thread t1(injestFromQueue, q);
  std::thread t2(injestFromQueue, q);
  std::thread t3(injestFromQueue, q);
  std::thread t4(injestFromQueue, q);
  std::thread t5(injestFromQueue, q);
  std::thread t6(injestFromQueue, q);
  std::thread t7(injestFromQueue, q);

  while (running) {
    std::cout << "Waiting for a client to connect...\n";
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    int socket_desc = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
    q->push(socket_desc);
  }

  return EXIT_SUCCESS;
}
