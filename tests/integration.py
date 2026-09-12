"""Run only inside a disposable network namespace with CAP_NET_ADMIN."""
import os
import socket
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cs2monitor as app
from test_updater import fixture

if os.environ.get('CS2_DISPOSABLE_NETWORK') != 'yes':
    raise SystemExit('Requires a disposable network namespace')
app.run(['ip','link','set','lo','up'])
for ip in ('193.23.195.8', '8.8.8.8'):
    app.run(['ip','addr','add',ip+'/32','dev','lo'])
app.run(['nft','add','table','inet','unrelated'])
data=fixture()
app.apply(data)

def probe(ip,port,kind,allowed):
    server=socket.socket(socket.AF_INET,kind); server.settimeout(0.4); server.bind((ip,port))
    if kind == socket.SOCK_STREAM: server.listen()
    client=socket.socket(socket.AF_INET,kind); client.settimeout(0.4)
    success=False
    try:
        if kind == socket.SOCK_STREAM:
            client.connect((ip,port)); connection,_=server.accept(); connection.close()
        else:
            client.sendto(b'test',(ip,port)); server.recvfrom(20)
        success=True
    except (TimeoutError,OSError): pass
    finally: client.close(); server.close()
    assert success == allowed, (ip,port,kind,success)

for protocol in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
    probe('193.23.195.8',27013,protocol,False)
    probe('193.23.195.8',27014,protocol,True)
    probe('8.8.8.8',27015,protocol,False)
# A successful update removes a released endpoint, but retains an unrelated table.
data['items']=data['items'][:2]; data['count']=2
app.apply(data)
for protocol in (socket.SOCK_STREAM,socket.SOCK_DGRAM): probe('193.23.195.8',27013,protocol,True)
app.run(['nft','list','table','inet','unrelated'])
# Failed atomic replacement leaves the previous table intact.
try: app.run(['nft','-f','-'],'delete table inet cs2monitor\nthis is invalid\n')
except Exception: pass
assert app.table_exists()
for protocol in (socket.SOCK_STREAM,socket.SOCK_DGRAM): probe('8.8.8.8',27016,protocol,False)
app.run(['nft','delete','table','inet','cs2monitor'])
app.apply(data, fresh=False)  # Simulate reboot restoration from saved state.
assert app.table_exists()
app.run(['nft','delete','table','inet','cs2monitor'])
app.run(['nft','list','table','inet','unrelated'])
print('PASS: real TCP/UDP filtering, exact ports, subnet scope, release, atomic failure, restore, unrelated rules')
