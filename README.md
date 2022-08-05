# RFID-Gate
Security gate for library inventory management using rfid

In this project we will create an RFID security gate. The client contains 3 boxes:
1. Controller
2 + 3. RFID reader + Antenna + LED

The controller that we use is ESP32. It is connected to both RFID modules, and to an ethernet port that leads to a server.
We used multitask options of ESP32 to use both cores.
For now we need to hard code the url of the server the we trasfer our barcodes, besides that, it is plug and play system.
We are using get method with query parameters, but it also can be used with other methods,  depends on the database design.
