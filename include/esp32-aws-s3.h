#include <SD.h>

class AWS_S3 {
 public:
    int put(String path, File payload);
    int put(String path, const byte payload[], int length);
};

