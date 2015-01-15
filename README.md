[![Build Status](https://api.shippable.com/projects/54b81bc85ab6cc135288bf48/badge?branchName=master)](https://app.shippable.com/projects/54b81bc85ab6cc135288bf48/builds/latest)

```
             _         _   _       ____                      
            / \  _   _| |_| |__   |  _ \ _ __ _____  ___   _ 
           / _ \| | | | __| '_ \  | |_) | '__/ _ \ \/ / | | |
          / ___ \ |_| | |_| | | | |  __/| | | (_) >  <| |_| |
         /_/   \_\__,_|\__|_| |_| |_|   |_|  \___/_/\_\\__, |
                                                       |___/ 



        User @ Home                         User @ Office   
            or                                    +         
      Identity Required                           |         
            +                               (Whitelisted IP)
            |                                     |         
            |                                     |         
            |         +-----------------+         |         
            |         |                 |         |         
            +-----------+   Auth        |         |         
                      | |   Proxy     +-----------+         
                      | | +--+        | |                   
                      +-----------------+                   
                        | |  |        |                     
          +----------+  | |  |        |                     
          |          <--+ |  |        |                     
          |  GitHub  |    |  |        |                     
          |          +----+  |        |                     
          +----------+       |        |                     
                          +--+        |                     
                    GitHub Profile    |                     
                  included in headers |                     
                          |           |                     
          +-------+   +---v---+   +---v---+   +-------+     
          |       |   |       |   |       |   |       |    Sites running on ports inaccessible 
          | Site1 |   | Site2 |   | Site3 |   | Site4 |    from public internet. Only allow
          |       |   |       |   |       |   |       |    http ingress from authproxy machine.
          +-------+   +-------+   +-------+   +-------+     
```
