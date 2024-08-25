import socket

from command_protocol import CommandProtocol

PROTOCOL = CommandProtocol()

def get_ssids():
  request_header = PROTOCOL.allocate('request_header')
  request_header.fields['type'] = PROTOCOL.enum('request_type', 'scan')
  client_socket.send(request_header.pack())

  response_header = PROTOCOL.allocate('response_header')
  response_header.unpack(client_socket.recv(response_header.size))

  print(PROTOCOL.enum_name('response_type', response_header.fields['type']))

  if response_header.fields['type'] != PROTOCOL.enum('response_type', 'ssids'):
    exit(0)

  ssids_message_header = PROTOCOL.allocate('ssids_message_header')
  ssids_message_header.unpack(client_socket.recv(ssids_message_header.size))
  print(ssids_message_header.fields['size'])

  ssids = []
  ssid_message = PROTOCOL.allocate('ssid_message')
  for index in range(ssids_message_header.fields['size']):
    ssid_message.unpack(client_socket.recv(ssid_message.size))
    ssid_name = client_socket.recv(ssid_message.fields['size'])
    ssids.append((ssid_message.fields['auth_mode'], ssid_name))
  return ssids

def send_credentials(auth_mode, ssid, password):
  request_header = PROTOCOL.allocate('request_header')
  request_header.fields['type'] = PROTOCOL.enum('request_type', 'credentials')
  request_buffer = request_header.pack()

  credentials_message = PROTOCOL.allocate('credentials_message')
  credentials_message.fields['auth_mode'] = 0
  credentials_message.fields['ssid_size'] = len(ssid)
  credentials_message.fields['password_size'] = len(password)
  request_buffer += credentials_message.pack() + ssid + password
  client_socket.send(request_buffer)

  response_header = PROTOCOL.allocate('response_header')
  response_header.unpack(client_socket.recv(response_header.size))
  print(PROTOCOL.enum_name('response_type', response_header.fields['type']))

if __name__ == '__main__':
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client_socket.connect(('192.168.4.1', 8080))

  print('Connected')

  # ssids = get_ssids()
  # print(ssids)

  send_credentials(0, b'Z807', b'PASSWORD')

