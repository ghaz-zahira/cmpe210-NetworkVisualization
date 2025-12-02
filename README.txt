Read Me:
Base commands for running things:

Terminal A: (controller start up)
ryu-manager simple_controller.py

Terminal B: (make topology)
either using custom_topo.py or a random one
The one I've been using is either custom_topo or:
sudo mn --topo=tree,depth=2,fanout=2 --controller=remote,ip=127.0.0.1,port=6653 --switch ovsk,protocols=OpenFlow13

Terminal C: (start up frontend)
python3 -m http.server 8081


In the Browser to view the dashboard: 
http://127.0.0.1:8081/dashboard.html


NOTE: Prior to rerunning after changes to controller file please run:
sudo mn -c