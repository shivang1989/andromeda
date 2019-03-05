Java.perform(function(){
    console.log("Inside perform");
    var allClasses = Java.enumerateLoadedClassesSync();
    send(allClasses)
});