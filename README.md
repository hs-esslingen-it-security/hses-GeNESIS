# **GeNESIS**: Generator for Network Evaluation Scenarios of Industrial Systems

Imagine yourself at the beach.
The waves role gently onto the shore, creating a rhythmic sound, and the sun is shining bright, embracing you with its warm light.
But somehow you can't relax.
Why?
Because you haven't figured out, how you handle your evaluation in your novel paper related to industrial networks yet.
But don't you worry, **GeNESIS** is here to help!

GeNESIS is a tool for generating realistic, exchangeable, and reproducible network layouts of industrial plants, including network devices, traffic profiles, and device configurations, e.g., firewall rulesets.
Therefore, GeNESIS is suitable to generate reference scenarios for the evaluation of new mechanisms or configurations, e.g., Quality of Service and Failure Tolerance.
Since GeNESIS can also optionally create rulesets with anomalies, it's suited for the evaluation of firewall ruleset optimization algorithms too.

## Licence and Citation
GeNESIS is licensed under the terms of the MIT license.

Our paper has been submitted to the [EFTA 2024](https://2024.ieee-etfa.org).
If you use GeNESIS in one of your papers, please cite:
```
# TODO: Include bibtex here
```

## Installation
Before you start, you should install the requirements and the GeNESIS module itself:
```
cd hses-genesis
pip install -r requirements.txt
pip install .
```

## Execution
GeNESIS can be launched with several different arguments:
```
optional arguments:
  -h, --help            show this help message and exit
  -j JSON, --json JSON  location of json configuration file.
  -g GENESIS_TAG, --genesis_tag GENESIS_TAG
                        GeNESIS-TAG of a previous run.
  -d, --default_run     start GeNESIS with the default configuration (./resources/example_config.json).
  -n, --new_configuration
                        start the Interactive GeNESIS Configuration Generator to create a new configuration.
  -o OUTPUT_LOCATION, --output_location OUTPUT_LOCATION
                        set the output location for generated files.
```
Normally, if no arguments are given, GeNESIS will generate a random new configuration before its actual execution.
The arguments `-j, -g, -d`, and `-n` define different possibilities to provide GeNESIS with specific configurations instead of random ones.
With the help of the `-j` flag, you can specify the location of a valid .json configuration file.
If you don't want to bother yourself with the syntax of the configuration files yet, we recommend using the `-n` tag.
This will start the Interactive GeNESIS Configuration Generator before the actual execution of GeNESIS, i.e., you will be guided through the creation process of a new configuration file.
Alternatively, if another run has already been executed, you may provide the provided GeNESIS-TAG from that run with the `-g` flag.
Notice, that the genesis tag must have the same version number (`GeNESIS:<version_number> ...`) as your GeNESIS distribution to guarantee correct reproduction of the previous run.
If `-d` is provided, GeNESIS will run with the default settings as specified in [./GeNESIS/resources/example_config.json](./GeNESIS/resources/example_config.json).

The output of each generation iteration of GeNESIS is saved within an output folder created by GeNESIS inside the [GeNESIS folder](./GeNESIS/).
However, if you want to save your output in a specific location, you may specify that path with the `-o` flag.

## Run Configuration
GeNESIS generation process is customizable by providing a valid .json configuration file.
An example of this can be found [here](./GeNESIS/resources/example_config.json).
In the following, the effects of each parameter on the generation process will be discussed briefly.

### Reproducibility
Reproducibility is one, if not the central design philosophy of GeNESIS.
Hence, each random decision from GeNESIS is selected with the help of customizable seeds.
The overall generation process is separated into three logical steps:
1) generation of topology,
2) development of communication relations, and
3) generation of network configurations.

Within the configuration.json file, you can specify a specific seed for each of these steps.
In contrast to all other parameters, you do not have to specify any seed to create a valid configuration file.
If you don't specify a seed in the configuration.json file, GeNESIS chooses a random seed at the beginning of execution.
Additionally, you can define the number of iterations of a specific step.
However, notice GeNESIS will increase the corresponding seed in every iteration of a step to provide new results in every iteration.
```
...
"steps": {
   "TOPOLOGY": {
      "iterations": 1,
      "seed": 1
   },
   "COMMUNICATION_RELATIONS": {
      "iterations": 1,
      "seed": 1
   },
   "NETWORK_CONFIGURATIONS": {
      "iterations": 1,
      "seed": 1
   }
},
...
```

## Topology
The generated networks are organized in a tree-like structure with a customizable depth.
Each layer of the tree has an associated type of ether *connectivity*, *aggregated control*, or *process*.
The *connectivity* type is dedicated for the root layer only and the *process* type is for the last layer, i.e., where the leave nodes of the tree are located.
Every layer in-between is of type *aggregated control*.
To visualize this concept:

```
                            connectivity
                         /                 \
               aggregated control       aggregated control
                   /     \                 /       \
            process       process   process         process
```
Each node (hereinafter referred to as **layer instance**) in this structure is a self-contained subnet, connected to other layer instances by routers.
This structure reflects common industry topologies and is represented accordingly in the [example configuration files](./GeNESIS/resources).
However, you can also define other setups with different sequences of layer types in your config file - which wouldn't be that realistic though.
But don't worry, we don't judge.

The depth of your tree-like network is given implicitly by the number of layer definitions you provide within your configuration file:
```
...
"layer_definitions": [
   ...
   {
      "layer_type": "AGGREGATED_CONTROL",
      "per_upper_layer": 2,
      "switch_count": 2,
      "devices_per_switch": 2,
      "structure": {
         "STAR": 0,
         "RING": 9,
         "LINE": 1,
         "MESH": 0
      }
   },
   ...
]
...
```

As depicted, per layer definition you can configure different other attributes besides its type.
The following are the detailed descriptions of each configuration parameter:
- `per_upper_layer`: the number of layer instances generated per layer instance in the next upper layer.
- `switch_count`: the number of additional layers created in each layer instance in addition to default switches needed for basic connectivity.
- `devices_per_switch`: the number of end devices connected to each switch.
- `structure`: description of the weighted probabilities in which specific structures are chosen for layer instances. In the given example 9/10 layer instances are instantiated as a ring network and every 10<sup>th</sup> layer instance is generated as a line network.

### Device Roles

GeNESIS supports six different device roles:
routers, servers, controllers, switches, IT devices, and OT devices.
The number of devices with four of these roles can be defied in your configuration.json:
```
...
"layer_device_count_configuration": {
   "CONNECTIVITY": {
      "SERVER": 1,
      "IT_END_DEVICE": 0,
      "OT_END_DEVICE": 0,
      "CONTROLLER": [0,0]
   },
   ...
}
...
```
- `SERVER`: This is a fixed value, i.e., what you type in is the number of switches you get per layer instance.
- `CONTROLLER`: This is a random range, i.e. you can specify the two endpoints and GeNESIS will generate a randomized number of devices in that range.
To get a fixed number of controllers instead, be sure to supply the same number in both endpoints.
- `IT/OT_END_DEVICE`: this is a truth value (0 or 1).
The actual number of IT/OT devices depends mainly on the number of switches in each layer instance, as well as the number of devices per switch.
However, you can choose to disable a certain type of end device in a layer instance by passing a 0 for IT/OT end devices.
If you want a specific type to occur set it to 1 instead.

|Role|(Normally) contained in|Count Customizable|Count per Layer Instance|
|:-:|:-:|:-:|:-|
|Router(s)|control, field||**1** for star and line. **2** for ring and mesh (redundancy).|
|Servers|enterprise|X|User-defined value in layer device count configuration.|
|Controller(s)|every layer|X|Random range with user-defined endpoints in layer device count configuration.|
|Switche(s)|every layer|X|Base count depends on the number of next child layer instances. A number of additional switches can be defined by users in layer definition.|
|IT/OT devices|control, field|X|Depends on number of end devices, switches in the layer definition and truth value in the layer device count configuration.|

## Communication
GeNESIS does not just generate comparable rulesets but also generates related traffic and security configurations, i.e., firewall rulesets for routers.

```
...
"communication": {
   ...
   "connection_count": 100,
   ...
},
...
```

### Communication Profiles
Allowed communication within the generated network is defined by so-called communication profiles and can be specified in the configuration.json.
Users have a choice between
1) strict isolation,
2) converged networks, and
3) distributed control.

The communication profiles are extensions of each other, i.e., converged networks inherit all properties of strict isolation and distributed control inherits all properties of converged networks.

1. Strict Isolation
   - All controllers may communicate with each other controller in neighboring layer instances along the same branch.
   - Any device may communicate with any other device within the same layer instance.
3. Converged Networks
   - All servers in the enterprise layer may communicate with any other device within the network, et vice versa.
4. Distributed Control
   - All controllers and servers may communicate with each other server and controller in the network.
   - All OT/IT devices may communicate with each other OT/IT device along the same branch.

As for each other configuration, the communication profiles are specified in the configuration.json file:
```
...
 "communication": {
      "traffic_profile" : "STRIC_ISOLATION" | "CONVERGED_NETWORKS" | "DISTRIBUTED_CONTROL",
      ...
    },
...
```
### Services

Each device is instantiated with a random selection of one or more services.
GeNESIS uses these services to define open ports and protocols of individual devices, which in turn are used to generate the traffic between different devices and the configurations, i.e., firewall rulesets, of routers.
Hence, in addition to the previously discussed communication profiles, two devices can only communicate with each other, if they both support the same protocols and share open ports.

|Service|Device Role|Protocol|Port|
|:-:|:-|:-|:-|
|SSH|Router, Server, Switch, IT device|TCP|22|
|Webserver|Router, Controller, Switch, IT/OT device|TCP|80,443|
|IP Camera|Server, IT device|RTSP, TCP|554|
|NETCONF|Router, Switch|TCP|830|
|OPC UA|Server, Controller|TCP|4840|
|ProfiNet|Controller, OT device|UDP|34962,34963,34964,53247|
|EtherCAT|Controller, OT device|UDP|0|


### Firewall Anomalies
To allow the traffic of valid communication pairs with paths over one or more routers that utilize whitelisting behavior, ACCEPT rules are created.
To create optimizable rulesets for optimization algorithms, GeNESIS allows you to configure an anomaly count.
If possible, GeNESIS will create as many anomalies in every generated ruleset as you defined.

```
...
"communication": {
   ...
   "anomaly_count": 10,
   ...
},
...
```
