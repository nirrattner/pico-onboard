import socket

from command_protocol import CommandProtocol

PROTOCOL = CommandProtocol()

if __name__ == '__main__':

  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client_socket.connect(('192.168.4.1', 8080))

  print('Connected')

  request = PROTOCOL.allocate('request')
  request.fields['type'] = PROTOCOL.enum('request_type', 'scan')
  client_socket.send(request.pack())

  print('Sent')

  response = PROTOCOL.allocate('response')
  response.unpack(client_socket.recv(response.size))

  print('Receive')
  print(PROTOCOL.enum_name('response_type', response.fields['type']))

  if response.fields['type'] != PROTOCOL.enum('response_type', 'ssids'):
    exit(0)

  ssids_header = PROTOCOL.allocate('ssids_header')
  ssids_header.unpack(client_socket.recv(ssids_header.size))
  print(ssids_header.fields['size'])

  ssid = PROTOCOL.allocate('ssid')
  for index in range(ssids_header.fields['size']):
    ssid.unpack(client_socket.recv(ssid.size))
    ssid_name = client_socket.recv(ssid.fields['size'])
    print(ssid_name)
    
