---RYU Controller Instructions----

Terminal A: (controller start up)
ryu-manager simple_controller.py

Terminal B: (make topology)
1.	Single Switch, Multiple Hosts
    a.	sudo mn --topo=single,3 --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13Linear Topology
2.	Linear Topology
    a.	sudo mn --topo=linear,3 --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
3.	Tree Topology
    a.	sudo mn --topo=tree,depth=2,fanout=2 --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
4. Custom Topo
    a.  sudo python3 custom_topo.py

Terminal C: (start up frontend)
python3 -m http.server 8081

Terminal D (if using custom_topo):
for br in $(sudo ovs-vsctl list-br); do
  echo "Installing flows on bridge: $br"
  sudo ovs-ofctl -O OpenFlow13 add-flow "$br" "priority=0,actions=CONTROLLER"
  sudo ovs-ofctl -O OpenFlow13 add-flow "$br" "priority=1000,dl_type=0x88cc,actions=CONTROLLER:65535"
done


In the Browser to view the dashboard: 
http://127.0.0.1:8081/dashboard.html


NOTE: Prior to rerunning after changes to controller file please run:
sudo mn -c

---PHP Controller Instructions---
Below are the instructions for running PHP controller to visualize the network through LLDP technology

Terminal A: Go to Path: sudo mn -c and sudo pkill -f controller_of13.php || true
Terminal B: Go to Path: sudo php controller_of13.php
Terminal C: Go to Path: sudo python3 custom_topo.py
Terminal D: 
for br in $(sudo ovs-vsctl list-br); do
  echo "Installing flows on bridge: $br"
  sudo ovs-ofctl -O OpenFlow13 add-flow "$br" "priority=0,actions=CONTROLLER"
  sudo ovs-ofctl -O OpenFlow13 add-flow "$br" "priority=1000,dl_type=0x88cc,actions=CONTROLLER:65535"
done
Terminal E: Go to Path: php -S 127.0.0.1:8080 and open https://127.0.0.1:8080/
