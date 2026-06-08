#ifndef LOGGER_H
#define LOGGER_H

void log_message(const char *format, ...);
void init_logger();
void close_logger();

#endif