#include <iostream>
#include <memory>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include "worker.h"
#include "server_error.h"

static constexpr std::string_view login = "user";
static constexpr std::string_view password = "P@ssW0rd";

Worker::Worker(std::string_view t, std::string_view h, std::string_view s)
    : type(t), hash(h), side(s), work_sock(-1)
{
    std::clog << "log: Выбранный вариант " << type << ':' << hash << ':' << side << std::endl;
    if (hash == "SHA224")
        hash_ptr = new CPP::SHA224;
    std::clog << "log: digest size: " << hash_ptr->DigestSize() << std::endl;
}

Worker::~Worker()
{
    delete hash_ptr;
}

void Worker::operator()(int sock)
{
    work_sock = sock;
    if (side == "client")
        auth_with_salt_at_client_side(*hash_ptr);
    calculate();
}

template <typename T> void Worker::calc()
{
    uint32_t num_vectors, vector_len;
    int rc;
    std::clog << "log: Start calculate with type " << typeid(T).name() << std::endl;
    rc = recv(work_sock, &num_vectors, sizeof num_vectors, 0);
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "Recv number of vetors error");
    std::clog << "log: Numbers of vectors " << num_vectors << std::endl;
    for (uint32_t i = 0; i < num_vectors; ++i) {
        rc = recv(work_sock, &vector_len, sizeof vector_len, 0);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Recv vector size error");
        std::clog << "log: Vector " << i <<" size " << vector_len << std::endl;
        std::unique_ptr<T[]> data (new T[vector_len]);
        std::clog << "log: Memory allocated at "  << data.get() << std::endl;
        rc = recv(work_sock, data.get(), sizeof(T) * vector_len, 0);
        std::clog << "log: Received "  << rc << " bytes of vector\n";
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Recv vector error");
        else if (sizeof(T) * vector_len != (uint32_t)rc) {
            throw vector_error("Vector error: mismatch actual and expected size");
        }
        T sum = 0;

        for (uint32_t i = 0; i < vector_len; ++i) {
            sum += data[i];
            if (std::is_integral<T>::value) {               // if interer types
                if (std::is_signed<T>::value) {             // if signed
                    if (data[i] > 0 and sum < 0 and (sum - data[i]) > 0) { //if overflow
                        sum = std::numeric_limits<T>::max();
                        break;
                    } else if (data[i] < 0 and sum > 0 and (sum - data[i]) < 0) {  //if undeflow
                        sum = std::numeric_limits<T>::min();
                        break;
                    }
                } else if (sum < data[i]) {                 // if unsigned, if overflow
                    sum = std::numeric_limits<T>::max();
                    break;
                }
            }
        }
        rc = send(work_sock, &sum, sizeof(T), 0);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Send result error");
        std::clog << "log: Sended vector summ " << sum << std::endl;
    }
}

void Worker::calculate()
{
    if (type == "uint16_t")
        Worker::calc<uint16_t>();
}

void Worker::auth_with_salt_at_client_side(CPP::HashTransformation& hash)
{
    int rc;
    std::string message(str_read());
    std::clog << "log: receive MESSAGE: " << message << std::endl;

    std::string hash_16(std::max(message.cbegin(), message.cend() - hash.DigestSize() * 2),
                        message.cend());
    message.erase(std::max(message.cbegin(), message.cend() - hash.DigestSize() * 2),
                  message.cend());
    if (message.empty())
        throw auth_error("Auth error: wrong auth message");
    std::clog << "log: detect HASH: " << hash_16 << std::endl;

    std::string salt_16 (std::max(message.cbegin(), message.cend() - 16), message.cend());
    message.erase(std::max(message.cbegin(), message.cend() - 16), message.cend());
    if (message.empty())
        throw auth_error("Auth error: wrong auth message");
    std::clog << "log: detect SALT: " << salt_16 << std::endl;

    std::clog << "log: detect USERNAME: " << message << std::endl;
    if (message != login)
        throw auth_error("Auth error: unknown user");
    std::clog << "log: username ok\n";
    // Calculate the expected hash
    std::string hash_16_calc;
    CPP::StringSource(salt_16 + std::string(password),
                      true,
                      new CPP::HashFilter(hash, new CPP::HexEncoder(new CPP::StringSink(hash_16_calc))));
    if (hash_16 != hash_16_calc)
        throw auth_error("Auth error: password mismatch");

    std::clog <<"log: auth success, sending OK\n";
    rc = send(work_sock, "OK", 2, 0);
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "`Send OK\' error");
}

#if defined DOUBLING_LOOP
std::string Worker::str_read()
{
    int rc;
    int buflen = BUFLEN;
    std::unique_ptr <char[]> buf(new char[buflen]);
    while (true) {
        rc = recv(work_sock, buf.get(), buflen, MSG_PEEK);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Recv string error");
        if (rc < buflen)
            break;
        buflen *= 2;
        buf = std::unique_ptr<char[]>(new char[buflen]);
    }
    std::string res(buf.get(), rc);
    rc = recv(work_sock, nullptr, rc, MSG_TRUNC);
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "Clear buffer error");
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}

#elif defined READING_TAIL

std::string Worker::str_read()
{
    int rc;
    int buflen = BUFLEN;
    std::unique_ptr <char[]> buf(new char[buflen]);
    rc = recv(work_sock, buf.get(), buflen, 0);
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "Recv string error");
    std::string res(buf.get(), rc);
    if (rc == buflen) {
        int tail_size;
        rc = ioctl(work_sock, FIONREAD, &tail_size);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "IOCTL error");
        if (tail_size > 0) {
            if (tail_size > buflen)
                buf = std::unique_ptr<char[]>(new char[tail_size]);
            rc = recv(work_sock, buf.get(), tail_size, 0);
            if (rc == -1)
                throw std::system_error(errno, std::generic_category(), "Recv string error");
            res.append(buf.get(), rc);
        }
    }
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}

#else
std::string Worker::str_read()
{
    int buflen = BUFLEN;
    std::unique_ptr <char[]> buf(new char[buflen]);
    int rc = recv(work_sock, buf.get(), buflen, 0);
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "Recv string error");
    std::string res(buf.get(), rc);
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}
#endif
