import re

def add_hook(ui):
    try:
        ui.tabWiget.setCurrentIndex(1)
        selected_method = str(ui.listWidget_methods.currentItem().text())
        print(selected_method)

        for i in selected_method.split(" "):
            if "(" in i:
                activity_without_params = i[:i.index("(")]

                # fetching only methodName from full method string
                tmp_str = activity_without_params.split(".")
                methodName = tmp_str[-1]

                # fetching classname where method is located
                lastindex_dot = activity_without_params.rindex(".")
                required_class_name = activity_without_params[:lastindex_dot]

                # fetching parameter count
                m = re.search('\((.*)\)', i)
                if m:
                    found = m.group(1)
                    print("parameters---> ", found)
                    param_cnt = 0
                    for item in found.split(","):
                        if item:
                            param_cnt = param_cnt + 1
                    print("parameter count ==> ", param_cnt)

        hook_jscode = """setTimeout(function(){
                            Java.perform(function(){
                                var MainActivity = Java.use('""" + str(required_class_name) + """');
    
                                // Number of params in this method = """ + str(param_cnt) + """
                                MainActivity.""" + str(methodName) + """.implementation = function(b){
                                
                                // Your Logic Goes Here. 
                                
                                console.log("Done");
                                }
                            });
    
                        }, 0);
        """

        ui.textEdit_javascript.setText(hook_jscode)
        return hook_jscode

    except Exception as e:
        print("Exception at add_hook: ", e)


