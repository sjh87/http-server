#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <map>
#include <regex>

#define HTTP_200 "HTTP/1.1 200 OK\r\n"
#define HTTP_404 "HTTP/1.1 404 Not Found\r\n"

class HTTPHeaders {
  std::map<std::string, std::string> headerMap;

  public:

    void add(std::string key, std::string value) {
      headerMap[key] = value;
    }

    void add(std::string key, int value) {
      headerMap[key] = std::to_string(value);
    }

    std::string toString() {
      std::string headerStr;

      for (auto [key, value]:headerMap) {
        headerStr += key + ":" + value + "\n";
      }

      return headerStr;
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
      return status.toString() + "\r\n" + headers.toString() + "\r\n" + body.toString();
    }
};

class HTTPRequest {
  std::string path;

  public:
    HTTPRequest(std::string req) {
      std::string route = req.substr(0, req.find("\r\n"));

      // std::string v = url.substr(0, url.find_first_of(" "));

      std::string p = route.substr(0, route.find_last_of(" "));
      path = p;
    }

    std::string getPath() {
      return path;
    }
};



HTTPResponse respond(HTTPRequest request) {
    std::string path = request.getPath();

    std::regex getEcho("GET /echo/[^/]*");
    if (std::regex_match(path, getEcho)) {
      std::string message = path.substr(path.find_last_of("/") + 1);

      HTTPHeaders headers = HTTPHeaders();
      headers.add("Content-Type", "text/plain");
      headers.add("Content-Length", message.size() + 1);

      HTTPBody body = HTTPBody(message);

      return HTTPResponse(200, headers, body);
    }

    std::string getRoot = "GET /";
    if (getRoot == path) return HTTPResponse(200);

    return HTTPResponse(404);
}

int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  // You can use print statements as follows for debugging, they'll be visible when running tests.
  std::cout << "Logs from your program will appear here!\n";

  // Uncomment this block to pass the first stage
  
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return EXIT_FAILURE;
  }
  
  // // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // // ensures that we don't run into 'Address already in use' errors
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
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return EXIT_FAILURE;
  }
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  int socket_desc = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);

  char req[4097] = { '\0' };

  ssize_t bytes_read = read(socket_desc, req, 4096);

  std::cout << "Client connected\n";

  if (bytes_read == -1) {
    std::cout << "error when reading request!";
    close(server_fd);

    return EXIT_SUCCESS;
  }

  HTTPRequest request = HTTPRequest(std::string(req));

  HTTPResponse response = respond(request);

  std::string responseStr = response.toString();

  send(socket_desc, responseStr.data(), responseStr.size() + 1, 0);

  close(server_fd);

  return EXIT_SUCCESS;
}
