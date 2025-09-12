#include "HardwareSerial.h"
#include "Argon2id_KDF.h"

Argon2id Argon;

const char* password = "kdfPassword";    // Key derivation password
const char* salt = "Salt123";    // // Key derivation salt
std::vector<uint8_t> pwd_vec (password, password+strlen(password));
std::vector<uint8_t> salt_vec (salt, salt+strlen(salt));

uint16_t MemorykB = 8;
uint16_t Iterations = 10;
uint8_t Output[32];


void SerialLogHandler(int level, const std::string_view module, const std::string_view msg) {
  const char* out = std::format("{}:  [{}] {}", LOG_LEVEL_STRINGS[level], module, msg).c_str();
  Serial.println(out);
}

void PrintArray(uint8_t Arr[], uint32_t size) {
  for (size_t i = 0; i < size; i++) {
    Serial.print(Arr[i], HEX);
    Serial.print(", ");
  }
}


int main(void) {
  Serial.begin(115200);   // Start the serial port
  Log::addLogger(SerialLogHandler);   // Add the log-handler to the logger

  // Derive Key from password and salt (salt and password length have to be >= 6 and memory has to be >= 8kB and divisible by 4 without remainder to comply with standards)
  Argon.deriveKey(pwd_vec, salt_vec, MemorykB, Iterations, sizeof(Output), Output);   

  PrintArray(Output, sizeof(Output));
  while(1) {}
}