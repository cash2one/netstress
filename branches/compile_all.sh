#!/bin/bash

make distclean
cp fullrandom.config .config
make all
mv netstress_fullrandom netstress.fullrandom

make distclean
cp fullstatic.config .config
make all
mv netstress_fullstatic netstress.fullstatic

make distclean
cp randomip_staticport.config .config
make all
mv netstress_randomip_staticport netstress.randomip_staticport

make distclean
cp staticip_randomport.config .config
make all
mv netstress_staticip_randomport netstress.staticip_randomport

sudo cp netstress.* /usr/bin/
sudo cp gui/netstress.py /usr/bin/netstress-gui
sudo cp gui/netstress.jpg /usr/bin/
