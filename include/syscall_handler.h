#ifndef SYSCALL_HANDLER_H
#define SYSCALL_HANDLER_H

#include <string>

void secureSystemCall(const std::string& username, const std::string& command);

#endif
