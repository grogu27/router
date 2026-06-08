#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_logger() {
    log_file = fopen("./logs/router.log", "w");
}

void close_logger() {
    if (log_file) fclose(log_file);
}

void log_message(const char *format, ...) {
    if (!log_file) return;
    
    pthread_mutex_lock(&log_mutex);
    
    time_t now;
    time(&now);
    
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(log_file, "[%s] ", time_str);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}