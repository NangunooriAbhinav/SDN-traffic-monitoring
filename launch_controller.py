#!/usr/bin/env python3
"""
launch_controller.py — Works with os-ken (no ryu-manager needed).
"""

import sys
import os

# Parse port before any framework imports
port = 6633
clean_argv = [sys.argv[0]]
i = 1
while i < len(sys.argv):
    if sys.argv[i] == "--ofp-tcp-listen-port" and i + 1 < len(sys.argv):
        port = int(sys.argv[i + 1])
        i += 2
    else:
        clean_argv.append(sys.argv[i])
        i += 1
sys.argv = clean_argv

# Add project dir to path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

try:
    from ryu.base.app_manager import AppManager
    from ryu.lib import hub
    from ryu.controller.controller import OpenFlowController
    FRAMEWORK = "ryu"
    OFP_HANDLER = "ryu.controller.ofp_handler"
except ImportError:
    from os_ken.base.app_manager import AppManager
    from os_ken.lib import hub
    from os_ken.controller.controller import OpenFlowController
    FRAMEWORK = "os_ken"
    OFP_HANDLER = "os_ken.controller.ofp_handler"

import logging
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


def main():
    LOG.info("Using framework: %s", FRAMEWORK)
    LOG.info("OpenFlow listen port: %d", port)

    # Configure the OpenFlow listen port
    try:
        from oslo_config import cfg
        CONF = cfg.CONF
        # Register the OFP options if not already registered
        try:
            CONF.register_opts([
                cfg.IntOpt('ofp_tcp_listen_port', default=port),
                cfg.StrOpt('ofp_listen_host', default='0.0.0.0'),
                cfg.BoolOpt('ofp_ssl_listen_port', default=None),
            ])
        except Exception:
            pass
        CONF([], project='ryu')
        CONF.set_override('ofp_tcp_listen_port', port)
        CONF.set_override('ofp_listen_host', '0.0.0.0')
    except Exception as e:
        LOG.warning("CONF setup: %s", e)

    # Load apps
    app_mgr = AppManager.get_instance()
    app_mgr.load_apps([OFP_HANDLER, "ryu_controller"])

    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))

    LOG.info("Controller started with %d services.", len(services))

    # Keep alive even if services list is empty
    try:
        if services:
            hub.joinall(services)
        else:
            LOG.info("No service greenlets returned. Keeping alive...")
            while True:
                hub.sleep(1)
    except KeyboardInterrupt:
        LOG.info("Shutting down...")
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()
