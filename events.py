# Author : Shivang Desai
#
# Project : Andromeda
#
# events.py : Initiator file for project.



import frida
import sys
import mainwindow, hook, banner
from PyQt5 import QtCore, QtGui, QtWidgets
import time
import convert

loadedClasses = []
selected_package_name = ""
required_class = ""
session = ""



def set_status(message):
    ui.statusBar.showMessage(str(message))

def connect_usb_device():
    try:
        device = frida.get_usb_device()
        ui.label_device.setText(str(device))
        set_status("Connection Established")
        ui.btn_goahead.setEnabled(True)
        # fetching package names
        apps = device.enumerate_applications()

        # apps variable contains all data about apps running on device/emulator
        # we need to fetch package name of apps
        fetch_package_names(apps)

    except Exception as e:
        ui.label_device.setText("No Device Found")
        set_status("No Device Found")


# fetch package names of apps on device/emulator
def fetch_package_names(apps):
    try:
        print("Fetching active processes on device/emulator.")
        print("found", len(apps), " instances running")
        i = 0
        ui.comboBox.clear()
        # loop to fetch all the package names running currently on device/emulator
        while i < len(apps):
            # print(apps[i].identifier)
            package_names_on_device = str(apps[i].identifier)
            ui.comboBox.addItem(package_names_on_device) # populating combo box with package names
            i = i+1
    except BaseException as e:
        print(e)
        set_status(e)



def fetch_classes():
    try:
        ui.listWidget_classes.clear()
        ui.listWidget_methods.clear()
        print("inside fetch_classes")
        global selected_package_name
        selected_package_name = str(ui.comboBox.currentText())
        print(selected_package_name)
        load_js_classes(selected_package_name)
    except Exception as e:
        print("Exception at fetch_classes: ", e)
        set_status(e)


def populate_classes(message, data):
    try:
        print("inside populate_classes")
        print(type(message['payload']))
        ui.listWidget_classes.clear()
        ui.listWidget_classes.addItems(message['payload'])
        global loadedClasses
        loadedClasses.clear()
        loadedClasses = message['payload']
    except Exception as e:
        print("Exception at populate_classes: ", e)
        set_status(e)


def load_js_classes(package_name):
    try:
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        device.resume(pid)
        time.sleep(1)
        global session
        session = device.attach(pid)

        print("Session in load_js_classes----->")
        print(session)

        with open("./scripts/fetchclasses_2.js") as file_obj:
            jscode = file_obj.read()
        script = session.create_script(jscode)
        script.on('message', populate_classes)
        script.load()
    except Exception as e:
        print("Exception while finding Package Name", e)
        # set_status(e)


# find desired class from long list of loaded classes in listView_classes widget
def find_class():
    try:
        ui.listWidget_classes.clear()
        print("finding classes")
        required_classes = []
        search_text = ui.lineEdit_findclass.text()
        global loadedClasses
        # print(loadedClasses)
        for i in loadedClasses:
            if search_text in i:
                print("class found:", i)
                ui.listWidget_classes.addItem(i)

        ui.btn_showMethods.setEnabled(True)
    except Exception as e:
        print("Exception at find_class: ", e)
        set_status(e)


def populate_methods(message, data):
    try:
        print("inside populate_methods")

        ui.listWidget_methods.clear()
        for i in message['payload'].split("###"):
            ui.listWidget_methods.addItem(i)
    except Exception as e:
        ui.listWidget_methods.addItem("No Methods Found.")
        print("populate_methods exception: ", e)
        set_status(e)


def load_methods():
    try:
        global required_class
        required_class = str(ui.listWidget_classes.currentItem().text())

        jscode = """setTimeout(function(){
                    Java.perform(function(){
                        console.log("Inside perform, fetching methods");
    
                        var obj = Java.use('""" + required_class + """')
                        var loaded_methods = obj.class.getDeclaredMethods();
                        var methods = "";
                        for(var i=0; i<loaded_methods.length; i++){
                            methods = methods + loaded_methods[i].toString() + "###";
                        }
                        send(methods);
                    });
                    
                    }, 0);"""

        global session
        print("Session in load_methods ----> ")
        print(session)
        script = session.create_script(jscode)
        script.on('message', populate_methods)
        script.load()
    except Exception as e:
        print("Exception while loading methods: ", e)
        set_status(e)


def refresh_classes():
    try:
        with open("./scripts/fetchclasses_2.js") as file_obj:
            jscode = file_obj.read()

        global session
        print("Session in load_methods ----> ")
        print(session)
        script = session.create_script(jscode)
        script.on('message', populate_classes)
        script.load()
    except Exception as e:
        print(e)



# ------------------ Tab 2 - "Hook" tab

def setup_hook():
    try:
        global session
        hook_jscode = hook.add_hook(ui)
        # print(hook_jscode)
    except Exception as e:
        print("Exception at setup_hook: ", e)
        set_status(e)


def hook_message(message, data):
    try:
        print("Inside hook_message:")
        print(message['payload'])
        # ui.listWidget_jsoutput.addItems(message['payload'])
        ui.textEdit_jsoutput.setText(message['payload'])
    except Exception as e:
        print(e)

def load_hook_script():
    try:
        jscode = ui.textEdit_javascript.toPlainText()
        #print(jscode)

        global session
        script = session.create_script(jscode)
        script.on('message', hook_message)
        script.load()
        print("script loaded")
        ui.textEdit_jsoutput.setText("Script Loaded Successfully")

    except Exception as e:
        print(e)



# ------------------ Tab 3 - "Analyze" tab
#
# def setup_analyze():
#     return
#
#
# def analyze_message(message, data):
#     return
#
# def load_analyze_script():
#     try:
#         jscode = ui.textEdit_analyze_javascript.toPlainText()
#         #print(jscode)
#
#         global session
#         script = session.create_script(jscode)
#         script.on('message', analyze_message)
#         script.load()
#         print("script loaded")
#     except Exception as e:
#         print(e)


# ------------------ Tab 3 - "Memory" tab

def ascii_hex_setup():
    try:
        search_string = ui.lineEdit_string.text()
        hex_string = convert.ascii_to_hex(search_string)
        ui.lineEdit_hex.clear()
        ui.lineEdit_hex.setText(hex_string)
    except Exception as e:
        print("Exception @ ascii_hex_setup : ", e)



def address_handler(message, data):
    try:
        output = message['payload']
        ui.listWidget_address.clear()
        for item in output.split("###"):
            ui.listWidget_address.addItem(item)
        set_status("Scanning Complete. Address Loaded.")
    except Exception as e:
        print("Exception @ address_handler: ", e)


def search_memory():
    try:
        ui.listWidget_address.clear()
        set_status("Scanning Address for pattern")
        read_mem_flag = ui.checkBox_readable.isChecked()   # True if Readable checkbox is ticked, else False
        write_mem_flag = ui.checkBox_writable.isChecked()  # True if Writable checkbox is ticket, else False
        prot = "r--"  # Setting Protection by default to "r--"

        if read_mem_flag:
            prot = "r--"
        if write_mem_flag:
            prot = "-w-"
        if read_mem_flag and write_mem_flag:
            prot = "rw-"

        if ui.lineEdit_hex.text() == "":
            pattern = convert.ascii_to_hex(ui.lineEdit_string.text())
        else:
            pattern = ui.lineEdit_hex.text()

        mem_js_code = """
                var ranges = Process.enumerateRangesSync({protection: '%s', coalesce: true});
                var range;
                var output;
                function analyzeAddress(){
                    range = ranges.pop();
                    if(!range){
                        send(output);
                        return;
                    }
        
                    Memory.scan(range.base, range.size, '%s', {
                        onMatch: function(address, size){
                                output = output + "###Pattern found at: " + address.toString();
                            }, 
                        onError: function(reason){
                                output = output + "###Scanning Error: " + reason; 
                            }, 
                        onComplete: function(){
                                analyzeAddress();
                            }
                        });
                }
                analyzeAddress();
        """ % (prot, pattern)

        global session
        script = session.create_script(mem_js_code)
        script.on('message', address_handler)
        script.load()
        print("script loaded")

    except Exception as e:
        print("Exception @ search_memory: ", e)




def write_memory_handler(message, data):
    try:
        print(message)

    except Exception as e:
        print("Exception at write_memory_handler: ", e)


def write_memory():
    try:
        addr = int(ui.lineEdit_address.text(), 16)  # converting hex to int
        write_hex = ui.lineEdit_hex.text()
        write_bytes = "[" + ','.join(["0x%02x" % int(x, 16) for x in write_hex.split(' ')]) + "]"


        write_js_code = """
            Memory.writeByteArray(ptr('0x%x'), %s);
        """ % (addr, write_bytes)

        global session
        script = session.create_script(write_js_code)
        script.on('message', write_memory_handler)
        script.load()
        print("script loaded")
        req_string = "Memory address over-write @ " +  str(addr)
        ui.listWidget_output.addItem(req_string)


    except Exception as e:
        print("Exception @ write_memory: ", e)





if __name__ == "__main__":
    print(banner.get_banner())
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = mainwindow.Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()


    ui.btn_connect.clicked.connect(lambda: connect_usb_device())
    ui.btn_goahead.clicked.connect(lambda: fetch_classes())

    # -------- Tab 1 "List Tab" buttons
    ui.btn_find.clicked.connect(lambda: find_class())
    ui.btn_showMethods.clicked.connect(lambda: load_methods())
    ui.btn_hook.clicked.connect(lambda: setup_hook())
    ui.btn_refresh.clicked.connect(lambda: refresh_classes())
    # ui.btn_analyze.clicked.connect(lambda: setup_analyze)


    # -------- Tab 2 "Hook Tab" buttons
    ui.btn_loadscript.clicked.connect(lambda: load_hook_script())



    # -------- Tab 3 "Memory Tab" buttons
    ui.btn_hex.clicked.connect(lambda: ascii_hex_setup())
    ui.btn_search.clicked.connect(lambda: search_memory())
    ui.btn_write.clicked.connect(lambda : write_memory())


    sys.exit(app.exec_())
