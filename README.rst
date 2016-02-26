==================================
Xipe - Network Discovery Scanner
==================================

This command line tool allows the user to connect to a Threat Stack account and retrieve the information contained
within an account. It is important to note that this script was not created  or is supported by Threat Stack.
Use under your own risk.

Usage
-----

.. code-block:: sh

    usage: xipescan.py [-h] [-d <IP List> <Output File Name>]

    Xipe - Network Discovery Scanner.

    optional arguments:
      -h, --help            show this help message and exit
      -d <IP List> <Output File Name>, --discoverfromfile <IP List> <Output File Name>
                            performs a discovery scan on the hosts in the file and
                            creates an output file containing active hosts.


Quick Start
-----------
First, install the libraries and set a default account:

.. code-block:: sh

    $ pip install python-nmap iptools

.. code-block:: sh

    $ ./xipescan.py -h

