  /****************************************************************************************************************************
  WebClient_SSL.ino - Dead simple SSL WebClient for Ethernet shields

  EthernetWebServer_SSL is a library for the Ethernet shields to run WebServer and Client with/without SSL
  Use SSLClient Library code from https://github.com/OPEnSLab-OSU/SSLClient

  Built by Khoi Hoang https://github.com/khoih-prog/EthernetWebServer_SSL
 *****************************************************************************************************************************/

// This sample sketch connects to SSL website (https://www.arduino.cc/asciilogo.txt)
// Generate trust_achors.h at https://openslab-osu.github.io/bearssl-certificate-utility/

#include <ArduinoJson.h>
#include <StreamUtils.h>
#include "./defines.h"

// You must have SSL Certificates here
#include "./trust_anchors.h"

// if you don't want to use DNS (and reduce your sketch size)
// use the numeric IP instead of the name for the server:
// Raw IP address not accepted in SSL
//IPAddress server_host(104, 22, 48, 75);

#define INBUFFSIZE 500
#define TAGSQUEUE  200
#define TAG_TIMEOUT 1500

struct Tag
{
  char epc[12];
  bool set;
  bool notified;
  unsigned long timestamp;
};

char test[] = {'t', 'e', 's', 't'};

Tag tags[TAGSQUEUE] = {0};
TaskHandle_t postHandler;
TaskHandle_t parseHandler;

unsigned int CRC_Table[256]={ 
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
  0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
  0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
  0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
  0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
  0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
  0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
  0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
  0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
  0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
  0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
  0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
  0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
  0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
  0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
  0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
  0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
  0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
  0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
  0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
  0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
  0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
  0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
  0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
  0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
  0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
  0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0 
};

byte mac1[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x01 };
const char server_host[] = "libraries.technion.ac.il"; // leave this alone, change only above two
const uint16_t server_port = 443;
auto http_timeout = millis();

// Choose the analog pin to get semi-random data from for SSL
// Pick a pin that's not connected or attached to a randomish voltage source
const int rand_pin = A0;

// Initialize the SSL client library
// Arguments: EthernetClient, our trust anchors
EthernetClient client;
EthernetSSLClient sslClient(client, TAs, (size_t)TAs_NUM);

// Variables to measure the speed
unsigned long beginMicros, endMicros;
unsigned long byteCount = 0;

bool printWebData = true;  // set to false for better speed measurement

unsigned int CRC16Check(unsigned char *ptr, unsigned char DataLen) 
{
  unsigned short CRC; 
  unsigned char DataReg; 
  CRC=0xffff;
  while(DataLen--!=0) 
  {
    DataReg=(unsigned char) (CRC/256); 
    CRC<<=8; 
    CRC^=CRC_Table[DataReg^*ptr]; 
    ptr++;
  }
  return CRC; 
}

void read_multi(HardwareSerial * ser) 
{
  unsigned char cmd[] = {0xAA,0xAA,0xFF,0x08,0xC1,0x00,0x05,0x00,0x00,0x22,0x1B};
  for(int i=0;i<11;i++)ser->write(cmd[i]);
}

bool epccmp(char*epc1, char*epc2)
{
  for (int i = 0; i < 12; i++)
  {
    if (epc1[i] != epc2[i])return false;
  }
  return true;
}

void printTag(char * epc)
{
  
  Serial.print(epc[11],HEX);
  
}

void printTagToSSL(char * epc){
  for( int i=0;i<12;i++)sslClient.print(epc[i]);
  sslClient.println();
}

void parseUHFCom(HardwareSerial * ser, int * index, unsigned char * buff, int device)
{
  unsigned char found_tag_header[] = {0xAA, 0xFF, 0x18, 0xC1, 0x00};
  while (ser->available())
  {
    char c = ser->read();

    if (c == 0xAA && *index==-1) // start cfg_packet
    {
      *index = 0;
    }
    else if (*index == 26) // the buffer should hold a full EPC tag
    {
      char tmp[12];
      memcpy(tmp, buff + 9, 12);

      bool found = false;
//      if (millis() - tags[i].timestamp > tag_timeout) // see if left
//        {
//          tags[i].set = false;
//
//          if (tags[i].notified)
//          {
//            Serial.print(epc); Serial.println(",out");
//
//            inputPayload += String("{\"type\":\"out\",\"barcode\":\"");
//            inputPayload += epc;
//            inputPayload += String("\",\"createdAt\":\"");
//            inputPayload += timeClient.getFormattedDate() + String("\"},");
//          }
//        }
//        else
//        {
//          if (tags[i].count > min_count && !tags[i].notified) // on
//          {
//
//            tags[i].notified = true;
//
//            Serial.print(epc); Serial.println(",in");
//
//            inputPayload += String("{\"type\":\"in\",\"barcode\":\"");
//            inputPayload += epc;
//            inputPayload += String("\",\"createdAt\":\"");
//            inputPayload += timeClient.getFormattedDate() + String("\"},");
//
//          }
//        }

      for (int i = 0; i < TAGSQUEUE; i++)
      {
        if (tags[i].set && epccmp(tmp, tags[i].epc))
        {
          found = true;
          break;
        }
      }

      if (!found)
      {

        Tag newTag;
        newTag.set = true;
        newTag.timestamp = millis();
        newTag.notified = false;
        memcpy(newTag.epc, tmp, 12);

        for (int i = 0; i < TAGSQUEUE; i++)
        {
          if (!tags[i].set)
          {
            tags[i] = newTag;
            
            Serial.println("FOUND TAG:");
            Serial.print("Using index ");Serial.println(i);
            printTag(tmp);
            Serial.println();
//            Serial.print("*******Device number : ");
//            Serial.print(device);
//            Serial.println(" *******");

            break;
          }
        }
      }

      *index = -1;
    }
    else
    {
      if (*index >= 0) // fill buffer after the $ arrived
      {
        buff[*index] = c;

        if (*index < INBUFFSIZE)
        {
          *index = (*index)+1;
        }
        else
        {
          *index=-1;
        }
        if (*index == 5) // make sure its a tag read response else reset index
        {          
          for(int i=0;i<5;i++)
          {
            if(buff[i]!=found_tag_header[i])
            {
              *index=-1;
              break;
            }
          }
        }
      }
    }
  }
}

void send_http(char* barcode) {
  if (sslClient.connected()) {
    if(millis() - http_timeout > 1000){
      Serial.print("GET /rf/?barcode=");
      
      Serial.println(" HTTP/1.1");
        if(barcode[11] == 0x01){
          sslClient.print("GET /rf/?barcode=000000000001");
          sslClient.println(" HTTP/1.1");
          sslClient.println("User-Agent: SSLClientOverEthernet");
          sslClient.println("Content-Type: application/json");
          sslClient.println("Host: libraries.technion.ac.il");
          sslClient.println("Connection: close");
          sslClient.println();
        http_timeout = millis();
        Serial.println("package sent");
      }else if(barcode[11] == 0x02){
          sslClient.print("GET /rf/?barcode=000000000002");
          sslClient.println(" HTTP/1.1");
          sslClient.println("User-Agent: SSLClientOverEthernet");
          sslClient.println("Content-Type: application/json");
          sslClient.println("Host: libraries.technion.ac.il");
          sslClient.println("Connection: close");
          sslClient.println();
          http_timeout = millis();
          Serial.println("package sent");
      }
      
    }else{
      Serial.println("package was not sent");
    }    
  } else if (!sslClient.connected()) {
    
    Serial.println("not connected");
    sslClient.connect(server_host, server_port);
    Serial.println("reconnecting");
    delay(1000);
    Serial.print("GET /rf/?barcode=");
    Serial.println(" HTTP/1.1");
    if(barcode[11] == 0x01){
        sslClient.print("GET /rf/?barcode=000000000001");
        sslClient.println(" HTTP/1.1");
        sslClient.println("User-Agent: SSLClientOverEthernet");
        sslClient.println("Content-Type: application/json");
        sslClient.println("Host: libraries.technion.ac.il");
        sslClient.println("Connection: close");
        sslClient.println();
        http_timeout = millis();
        Serial.println("package sent");
      }else if(barcode[11] == 0x02){
          sslClient.print("GET /rf/?barcode=000000000002");
          sslClient.println(" HTTP/1.1");
          sslClient.println("User-Agent: SSLClientOverEthernet");
          sslClient.println("Content-Type: application/json");
          sslClient.println("Host: libraries.technion.ac.il");
          sslClient.println("Connection: close");
          sslClient.println();
          http_timeout = millis();
          Serial.println("package sent");
      }
  }
}

void read_data() {
  while (sslClient.available()) {
    int len = sslClient.available();
    //Serial.println(len);
    Serial.println("reading data");
    if (len > 0)
    {
      byte buffer[80];

      if (len > 80)
        len = 80;

      sslClient.read(buffer, len);

      if (printWebData)
      {
        Serial.write(buffer, len); // show in the serial monitor (slows some boards)
      }

      byteCount = byteCount + len;
    }

    // if the server's disconnected, stop the sslClient:
    if (!sslClient.connected())
    {
      endMicros = micros();

      Serial.println();
      Serial.println("Disconnecting.");
      sslClient.stop();

      Serial.print("Received ");
      Serial.print(byteCount);
      Serial.print(" bytes in ");
      float seconds = (float)(endMicros - beginMicros) / 1000000.0;
      Serial.print(seconds, 4);
      float rate = (float)byteCount / seconds / 1000.0;
      Serial.print(" s, rate = ");
      Serial.print(rate);
      Serial.print(" kbytes/second");
      Serial.println();
    }
  }
}



void postTask( void * pvParameters )
{
  while (true)
  {
    
    for (int i = 0; i < TAGSQUEUE; i++)
    {
      // 
      if (tags[i].set && !tags[i].notified)
      {
        delay(10);
        Serial.println("SENDING TAG:");
        printTag(tags[i].epc);
        Serial.println();
        send_http(tags[i].epc);
        tags[i].notified = true;
      }else if (tags[i].set && (millis() - tags[i].timestamp)>TAG_TIMEOUT && tags[i].notified){
        tags[i].notified = false;
        tags[i].set = false;
        tags[i].epc[0] = 0;
        Serial.println("set tag to 0!!!!!!");
      }
      read_data();
      
    }
    
  }
}

void parsesUHFTask( void * pvParameters )
{
  unsigned char inbuff2[500];
  int inbuff_index2 = -1;
  unsigned char inbuff1[500];
  int inbuff_index1 = -1;

  while (true)
  {
    parseUHFCom(&Serial2, &inbuff_index2, inbuff2, 2);
    parseUHFCom(&Serial1, &inbuff_index1, inbuff1, 1);
  }
}

String DisplayAddress(IPAddress address)
{
 return String(address[0]) + "." + 
        String(address[1]) + "." + 
        String(address[2]) + "." + 
        String(address[3]);
}

void initEthernet()
{
#if USE_ETHERNET_PORTENTA_H7
  ET_LOGWARN(F("======== USE_PORTENTA_H7_ETHERNET ========"));
#elif USE_NATIVE_ETHERNET
  ET_LOGWARN(F("======== USE_NATIVE_ETHERNET ========"));
#elif USE_ETHERNET_GENERIC
  ET_LOGWARN(F("=========== USE_ETHERNET_GENERIC ==========="));  
#elif USE_ETHERNET_ESP8266
  ET_LOGWARN(F("=========== USE_ETHERNET_ESP8266 ==========="));
#elif USE_ETHERNET_ENC
  ET_LOGWARN(F("=========== USE_ETHERNET_ENC ==========="));  
#else
  ET_LOGWARN(F("========================="));
#endif

#if !(USE_NATIVE_ETHERNET || USE_ETHERNET_PORTENTA_H7)

#if (USING_SPI2)
  #if defined(CUR_PIN_MISO)
    ET_LOGWARN(F("Default SPI pinout:"));
    ET_LOGWARN1(F("MOSI:"), CUR_PIN_MOSI);
    ET_LOGWARN1(F("MISO:"), CUR_PIN_MISO);
    ET_LOGWARN1(F("SCK:"),  CUR_PIN_SCK);
    ET_LOGWARN1(F("SS:"),   CUR_PIN_SS);
    ET_LOGWARN(F("========================="));
  #endif
#else
  ET_LOGWARN(F("Default SPI pinout:"));
  ET_LOGWARN1(F("MOSI:"), MOSI);
  ET_LOGWARN1(F("MISO:"), MISO);
  ET_LOGWARN1(F("SCK:"),  SCK);
  ET_LOGWARN1(F("SS:"),   SS);
  ET_LOGWARN(F("========================="));
#endif

#if defined(ESP8266)
  // For ESP8266, change for other boards if necessary
  #ifndef USE_THIS_SS_PIN
    #define USE_THIS_SS_PIN   D2    // For ESP8266
  #endif

  ET_LOGWARN1(F("ESP8266 setCsPin:"), USE_THIS_SS_PIN);

  #if ( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )
    // For ESP8266
    // Pin                D0(GPIO16)    D1(GPIO5)    D2(GPIO4)    D3(GPIO0)    D4(GPIO2)    D8
    // EthernetGeneric    X                 X            X            X            X        0
    // Ethernet_ESP8266   0                 0            0            0            0        0
    // D2 is safe to used for Ethernet, Ethernet2, Ethernet3, EthernetLarge libs
    // Must use library patch for Ethernet, EthernetLarge libraries
    Ethernet.init (USE_THIS_SS_PIN);

  #elif USE_CUSTOM_ETHERNET
  
    // You have to add initialization for your Custom Ethernet here
    // This is just an example to setCSPin to USE_THIS_SS_PIN, and can be not correct and enough
    Ethernet.init(USE_THIS_SS_PIN);
  
  #endif  //( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )

#elif defined(ESP32)

  // You can use Ethernet.init(pin) to configure the CS pin
  //Ethernet.init(10);  // Most Arduino shields
  //Ethernet.init(5);   // MKR ETH shield
  //Ethernet.init(0);   // Teensy 2.0
  //Ethernet.init(20);  // Teensy++ 2.0
  //Ethernet.init(15);  // ESP8266 with Adafruit Featherwing Ethernet
  //Ethernet.init(33);  // ESP32 with Adafruit Featherwing Ethernet

  #ifndef USE_THIS_SS_PIN
    #define USE_THIS_SS_PIN   5   //22    // For ESP32
  #endif

  ET_LOGWARN1(F("ESP32 setCsPin:"), USE_THIS_SS_PIN);

  // For other boards, to change if necessary
  #if ( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )
    // Must use library patch for Ethernet, EthernetLarge libraries
    // ESP32 => GPIO2,4,5,13,15,21,22 OK with Ethernet, Ethernet2, EthernetLarge
    // ESP32 => GPIO2,4,5,15,21,22 OK with Ethernet3
  
    //Ethernet.setCsPin (USE_THIS_SS_PIN);
    Ethernet.init (USE_THIS_SS_PIN);
  
  #elif USE_CUSTOM_ETHERNET
  
    // You have to add initialization for your Custom Ethernet here
    // This is just an example to setCSPin to USE_THIS_SS_PIN, and can be not correct and enough
    Ethernet.init(USE_THIS_SS_PIN); 
  
  #endif  //( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )

#elif ETHERNET_USE_RPIPICO

  pinMode(USE_THIS_SS_PIN, OUTPUT);
  digitalWrite(USE_THIS_SS_PIN, HIGH);
  
  // ETHERNET_USE_RPIPICO, use default SS = 5 or 17
  #ifndef USE_THIS_SS_PIN
    #if defined(ARDUINO_ARCH_MBED)
      #define USE_THIS_SS_PIN   5     // For Arduino Mbed core
    #else  
      #define USE_THIS_SS_PIN   17    // For E.Philhower core
    #endif
  #endif

  ET_LOGWARN1(F("RPIPICO setCsPin:"), USE_THIS_SS_PIN);

  // For other boards, to change if necessary
  #if ( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )
    // Must use library patch for Ethernet, EthernetLarge libraries
    // For RPI Pico using Arduino Mbed RP2040 core
    // SCK: GPIO2,  MOSI: GPIO3, MISO: GPIO4, SS/CS: GPIO5
    // For RPI Pico using E. Philhower RP2040 core
    // SCK: GPIO18,  MOSI: GPIO19, MISO: GPIO16, SS/CS: GPIO17
    // Default pin 5/17 to SS/CS
  
    //Ethernet.setCsPin (USE_THIS_SS_PIN);
    Ethernet.init (USE_THIS_SS_PIN);
     
  #endif    //( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )

#else   //defined(ESP8266)
  // unknown board, do nothing, use default SS = 10
  #ifndef USE_THIS_SS_PIN
    #define USE_THIS_SS_PIN   10    // For other boards
  #endif

  #if defined(BOARD_NAME)
    ET_LOGWARN3(F("Board :"), BOARD_NAME, F(", setCsPin:"), USE_THIS_SS_PIN);
  #else
    ET_LOGWARN1(F("Unknown board setCsPin:"), USE_THIS_SS_PIN);
  #endif

  // For other boards, to change if necessary
  #if ( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC || USE_NATIVE_ETHERNET )
    // Must use library patch for Ethernet, Ethernet2, EthernetLarge libraries
  
    Ethernet.init (USE_THIS_SS_PIN);
  
  #elif USE_CUSTOM_ETHERNET
  
    // You have to add initialization for your Custom Ethernet here
    // This is just an example to setCSPin to USE_THIS_SS_PIN, and can be not correct and enough
    Ethernet.init(USE_THIS_SS_PIN);
    
  #endif  //( USE_ETHERNET_GENERIC || USE_ETHERNET_ENC )

#endif    // defined(ESP8266)

#endif    // #if !(USE_NATIVE_ETHERNET)

  // start the ethernet connection and the server:
  // Use DHCP dynamic IP and random mac
  uint16_t index = millis() % NUMBER_OF_MAC;
  // Use Static IP
  //Ethernet.begin(mac[index], ip);
  //Ethernet.begin(mac[index]);
  if (Ethernet.begin(mac1) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
  } else {
    Serial.print("  DHCP assigned IP ");
    Serial.println(Ethernet.localIP());
  }

#if !(USE_NATIVE_ETHERNET || USE_ETHERNET_PORTENTA_H7)
  ET_LOGWARN(F("========================="));
  
  #if defined( ESP32 )
    // Just info to know how to connect correctly
    // To change for other SPI
    ET_LOGWARN(F("Currently Used SPI pinout:"));
    ET_LOGWARN1(F("MOSI:"), PIN_MOSI);
    ET_LOGWARN1(F("MISO:"), PIN_MISO);
    ET_LOGWARN1(F("SCK:"),  PIN_SCK);
    ET_LOGWARN1(F("SS:"),   PIN_SS);
  #else
    #if defined(CUR_PIN_MISO)
      ET_LOGWARN(F("Currently Used SPI pinout:"));
      ET_LOGWARN1(F("MOSI:"), CUR_PIN_MOSI);
      ET_LOGWARN1(F("MISO:"), CUR_PIN_MISO);
      ET_LOGWARN1(F("SCK:"),  CUR_PIN_SCK);
      ET_LOGWARN1(F("SS:"),   CUR_PIN_SS);
    #else
      ET_LOGWARN(F("Currently Used SPI pinout:"));
      ET_LOGWARN1(F("MOSI:"), MOSI);
      ET_LOGWARN1(F("MISO:"), MISO);
      ET_LOGWARN1(F("SCK:"),  SCK);
      ET_LOGWARN1(F("SS:"),   SS);
    #endif
  #endif
  
  ET_LOGWARN(F("========================="));

#elif (USE_ETHERNET_PORTENTA_H7)
  if (Ethernet.hardwareStatus() == EthernetNoHardware) 
  {
    Serial.println("No Ethernet found. Stay here forever");
    
    while (true) 
    {
      delay(1); // do nothing, no point running without Ethernet hardware
    }
  }
  
  if (Ethernet.linkStatus() == LinkOFF) 
  {
    Serial.println("Not connected Ethernet cable");
  }
#endif

  Serial.print(F("Using mac index = "));
  Serial.println(index);

  Serial.print(F("Connected! IP address: "));
  Serial.println(Ethernet.localIP());
}

void setup()
{
  // Open serial communications and wait for port to open:
  Serial.begin(115200);
  Serial1.begin(115200, SERIAL_8N1, 17, 16);
  Serial2.begin(115200, SERIAL_8N1, 27, 26);
  
  read_multi(&Serial1);
  read_multi(&Serial2);
  //while (!Serial);

  //setup ethernet w5500 connection
  Serial.print("\nStart WebClient_SSL on " + String(BOARD_NAME));
  Serial.println(" with " + String(SHIELD_TYPE));
  Serial.println(ETHERNET_WEBSERVER_SSL_VERSION);

  initEthernet();
//  Ethernet.init(5);
//  delay(1000);
//  ET_LOGWARN(F("Currently Used SPI pinout:"));
//  ET_LOGWARN1(F("MOSI:"), PIN_MOSI);
//  ET_LOGWARN1(F("MISO:"), PIN_MISO);
//  ET_LOGWARN1(F("SCK:"),  PIN_SCK);
//  ET_LOGWARN1(F("SS:"),   PIN_SS);
//  //define mac and ip
//  uint16_t index = millis() % NUMBER_OF_MAC;
//  Serial.print(F("Using mac index = "));
//  Serial.println(index);
//  Ethernet.begin(mac[index]);
  
  Serial.print(F("Connected! IP address: "));
  Serial.println(Ethernet.localIP());
  while(DisplayAddress(Ethernet.localIP()) == "0.0.0.0"){
    uint16_t index = millis() % NUMBER_OF_MAC;
    Ethernet.init(5);
    Ethernet.begin(mac1);
    delay(1000);
    Serial.println("trying to connect");
  }
  

  // give the Ethernet shield a second to initialize:
  delay(1000);
  
  Serial.print("Connecting to : ");
  Serial.print(server_host);
  Serial.print(", port : ");
  Serial.println(server_port);
  sslClient.connect(server_host, server_port);
  delay(300);
  //setup each core task
  xTaskCreatePinnedToCore(
                    postTask,   /* Task function. */
                    "postTask",     /* name of task. */
                    40000,       /* Stack size of task */
                    NULL,        /* parameter of the task */
                    1,           /* priority of the task */
                    &postHandler,      /* Task handle to keep track of created task */
                    0);

  xTaskCreatePinnedToCore(
                    parsesUHFTask,   /* Task function. */
                    "parseTask",     /* name of task. */
                    10000,       /* Stack size of task */
                    NULL,        /* parameter of the task */
                    1,           /* priority of the task */
                    &parseHandler,      /* Task handle to keep track of created task */
                    1);
}

void loop()
{ 
  
}

//if(millis() - http_timeout > 500){
//      sslClient.println("GET /rf/?barcode=" + String(barcode) + " HTTP/1.1\r\nUser-Agent: SSLClientOverEthernet\r\nContent-Type: application/json\r\nHost: libraries.technion.ac.il\r\nConnection: close\r\n" );
//      http_timeout = millis();
