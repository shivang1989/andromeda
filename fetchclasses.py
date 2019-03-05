import frida, sys
import time
import events


def msg_from_js(message, data): # 'message' is dictionary
    allclasses = message['payload']


def load_js(package_name):
    try:
        # session = frida.get_usb_device().attach(package_name)

        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        device.resume(pid)
        time.sleep(1)
        session = device.attach(pid)

        with open("./scripts/fetchclasses_2.js") as file_obj:
            jscode = file_obj.read()
            script = session.create_script(jscode)
        #script.on('message', msg_from_js)
        script.on('message', events.populate_classes)
        script.load()

    except Exception as e:
        print("Exception while finding Package Name", e)
