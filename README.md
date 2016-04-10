# Tunnel TCP traffic over HTTP proxy

This is a toy program, play with it at your own risk. The HTTP proxy must support CONNECT method, and does not require authentication, or you could use HAProxy as backend. This program will drop any non-TCP traffic.

I copied lots of logic from [fqrouter](http://fqrouter.tumblr.com/post/51474945203/socks%E4%BB%A3%E7%90%86%E8%BD%ACvpn#_=_), its author is really smart!

## Usage:

Run the script as root:

~~~~~~~~
sudo ./tcp_over_http.py -x proxy_ip:proxy_port
~~~~~~~~

Add route table:

~~~~~~~~
sudo ip route add 1.2.3.4 dev tun0
~~~~~~~~

Test it:

~~~~~~~~
ssh 1.2.3.4
~~~~~~~~
