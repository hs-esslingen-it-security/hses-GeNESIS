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

Our paper has been accepted and presented at the [EFTA 2024](https://2024.ieee-etfa.org).
You can find a copy of the paper [here](https://github.com/hs-esslingen-it-security/hses-GeNESIS/blob/main/genesis-etfa-2024.pdf).
If you use GeNESIS in one of your papers, please cite:
```
@INPROCEEDINGS{bechtel2024,
    author={Bechtel, Lukas and Müller, Samuel and Menth, Michael and Heer, Tobias},
    title={{GeNESIS: Generator for Network Evaluation Scenarios of Industrial Systems}}, 
    booktitle={{IEEE International Conference on Emerging Technologies and Factory Automation (ETFA)}}, 
    year={2024},
    month = sep,
    address = {Padova, Italy}
}
```

## Installation
Before you start, you should install the requirements and the GeNESIS module itself:
```
pip install -r requirements.txt
pip install .
```

To check whether GeNESIS was installed correctly just execute:
```
python3 hses_genesis/main.py
```
This will start a generation cycle with the [`example_config.json`](./hses_genesis/resources/example_config.json) file and save the outputs in `<hses_genesis/output/example_config/>`.
During the generation, GeNESIS keeps you up to date about current processes and its general progress.

## Tutorial
We published a tutorial paper at the [Computation and Communication for Smart Systems Symposium (C2S3) 2025](https://www.hs-esslingen.de/informatik-und-informationstechnik/fakultaet/aktuelles/veranstaltungen/c2s3).
The paper showcases the most relevant features of GeNESIS**v1.2** and provides instructions on how to utilize GeNESIS for simulations in ns-3 and OMNeT++.
If you are interested in the simulation of network topologies generated with GeNESIS we refer to our paper available [here]().

## Execution
With no additional arguments provided, GeNESIS will start a generation cycle using the example config located [here](./hses_genesis/resources/example_config.json).
However, GeNESIS can be launched with several optional, different arguments:
```
optional arguments:
  -h, --help            show this help message and exit
  -j JSON, --json JSON  location of json configuration file.
  -g GENESIS_TAG, --genesis_tag GENESIS_TAG
                        GeNESIS-TAG of a previous run.
  -n, --new_configuration
                        start the Interactive GeNESIS Configuration Generator to create a new configuration.
  -o OUTPUT_LOCATION, --output_location OUTPUT_LOCATION
                        set the output location for generated files.
  -img, --export_graph_images
                        use this to export an image of the network topology on creation.
  -omnet, --export_omnet_files
                        use this to export the topology and packets configuration files for omnet++.
  -ns3, --export_ns3_files
                        use this to export the topology and packets configuration files for ns3.
  -yang, --export_yang_files
                        use this to export the all outputs in a single json file.
  -ipt, --export_iptables_files
                        use this to export the scurity configuration as iptables save files.
  -latag, --use_latex_tag
                        use this to get the genesis tag in latex parsable form.
```

### Arguments for Configuration Provision
The arguments `-j`, `-g`, and `-n` define different possibilities to provide GeNESIS with other configurations.
- With the help of the `-j` flag, you can provide a valid .json configuration file by passing it's absolute path.
  If you place your configuration file into the `hses_genesis/resources` folder, you can also pass the configuraiton file by it's name insted of it's absolute path.
- If you don't want to bother yourself with the syntax of the configuration files yet, we recommend using the `-n` tag.
This will start the Interactive GeNESIS Configuration Generator before the actual execution of GeNESIS, i.e., you will be guided through the creation process of a new configuration file.
- Alternatively, if another run has already been executed, you may provide the GeNESIS-TAG of that run with the `-g` flag.
This will result in GeNESIS recreating the exact same outputs as in the referenced run.
Hence, the genesis tag is useful to exchange information about data without actually providing the data.

> Notice, that the genesis tag must have the same version number (`GeNESIS:<version_number> ...`) as your GeNESIS distribution to guarantee correct reproduction of the previous run.
> If your GeNESIS version differs from the version of your tag, you can checkout the correct GeNESIS version with `git checkout tags/<version_number>`.

### Arguments for Output Specification
The output of each generation iteration of GeNESIS is saved within an output folder created by GeNESIS inside the [GeNESIS output folder](./hses_genesis/output).
However, if you want to save your output in a specific location, you can specify that path with the `-o` flag.

By default, GeNESIS outputs a `graph.graphml`-file including all informations about the generated network topology and security configurations.
The generated communication is stored in a separate `packets.csv`-file.
However, GeNESIS also provides some additional, optional output formats:
- By providing the `-yang` flag, GeNESIS outputs a ietf format conform yang.json file describing the generated network topology.
- By providing the `-ipt` flag, GeNESIS outputs a `iptables-save` file for each router, containing the generated security configurations.
- By providing the `-img` flag, GeNESIS outpus a vistual representation of the generated network topology as .png and .jpg.
- By providing the `-omnet` flag, GeNESIS outputs a ready to import folder to an omnet++ project.
  This fodler includes topology and traffic patterns to simulate.
- By provifing the `-ns3` flag, GeNESIS outputs a multiple files ready to be included in an ns3 project.
  The files include topology and traffic patterns to simulate.
- By providing the `-latag` flag, GeNESIS will return an alternative GeNESIS-tag.
  This tag is semantically identical but does not use the same compression logic as the default GeNESIS-tag.
  Additionally, the latag is insertable into any latex project without any additional adjustments.

## Configurability
The GeNESIS generation process is customizable by providing a valid .json configuration-file.
Examples of valid configurations are available [here](./hses_genesis/resources).

As GeNESIS basically operates in three different, consecutive steps, i.e., topology generation, communication generation, and security generation, the configuration file is also structured accordingly.
In the following sections, we will discuss the effects of each configurable parameter in each part of the configuration file briefly.

### Topology
The topology part of the configuration file contains iterations and layer definitions:
```
"topology": {
   "iterations": X,
   "layer_definitions": [
      ...
   ]
}
```
As for every step, you can specify the topology generation step to be executed multiple times, i.e., setting `"iterations": 2` will cause GeNESIS to generate 2 different topologies based on the given configurations.

For each layer definition, you can specify:
```
"layer_definitions":
   ...
   {
      "subnet_descendants": X,
      "switch_count": X,
      "max_hosts_per_switch": X,
      "host_types": {
         "SERVER": X,
         "IT_END_DEVICE": X,
         "OT_END_DEVICE": X,
         "CONTROLLER": X
      },
      "structure_distribution": {
         "STAR": X,
         "RING": X,
         "LINE": X,
         "MESH": X
      },
      "repetitions": X
   },
   ...
```

To explain the contents and impacts of the different parameters of a layer definition, one must first understand the hierarchical structure of indistrial networks.
For this, consider the following example topology:

```
layer 2                   [Subnet 1]
                         /          \
layer 1        [Subnet 2]            [Subnet 5]
              /          \          /          \
layer 0  [Subnet 3]  [Subnet 4][Subnet 6]  [Subnet 7]
```

As depicted, the generated networks are organized in hierarchical, tree-like structures.
The depth of these trees is given implicitly by the number of layer definitions you provide.

The layer definitions each define such a layer.
- `per_upper_layer` defines the number of subnets a layer contains for each subnet in the next higher layer, i.e., in the example above, layer 1 and layer 0 both have `"per_upper_layer": 2`.
- `switch_count` defines the number of switches containes in each subnet of the defined layer.
- `max_host_per_switch` defines the number of devices connected to each switch in each subnet of the defined layer.
- `host_types` defines the different kinds of devices found in each subnet of the defined layer.
GeNESIS supports four different host types: `SERVER`, `CONTROLLER`, `OT_END_DEVICE`, and `IT_END_DEVICE`.
You can specify the occurance of each of these types in two different ways:
First, by assigning them a specific number, and second, by setting their value to `-1`.
If a positive integer is provided, GeNESIS will generate that exact number of devices in each subnet of the defined layer.
If a negative integer is provided, GeNESIS will create devices of that type, until each switch of the subnet is connected to exactly `max_host_per_switch` switches.
- `structure_distribution` describes the structure type of the subnets of the defined layer.
This parameter is specified as a distribution, e.g., if you provide `{"RING": 1, "LINE":1}`, a generated subnet has a 50:50 chance to be either a ring or a line network.
- `repetitions` enables you to configure multiple layers at once.
For example, if layer 0 and layer 1 should have the exact same configurations, you can simply define them once and set `"repetitions": 2`.

### Communication
The communication part of the configuration file specifies iterations, communication profiles, and an upper connection count:
```
"communication": {
   "iterations": X,
   "traffic_profile": X,
   "upper_connection_count": X
}
```

As for every generation step, a user can configure GeNESIS to execute the communication generation step multiple times with the help of `"iterations"`.
> Note however, that the communication step is applied after every topology generation step. Hence, if you configure multiple iterations in both the topology and the communication step, GeNESIS will generate $topology.iterations * communication.iterations$ different evaluation scenarios.

For the definition of allowed communication in a network, GeNESIS uses so-called traffic profiles.
GeNESIS supports three different kinds of these traffic profiles: `"STRIC_ISOLATION"`, `"CONVERGED_NETWORKS"`, and `"DISTRIBUTED_CONTROL"`.

These communication profiles are extensions of each other, i.e., converged networks inherit all properties of strict isolation and distributed control inherits all properties of converged networks.

1. Strict Isolation
   - All controllers may communicate with each other controller in neighboring layer instances along the same branch.
   - Any device may communicate with any other device within the same layer instance.
3. Converged Networks
   - All servers in the enterprise layer may communicate with any other device within the network, et vice versa.
4. Distributed Control
   - All controllers and servers may communicate with each other server and controller in the network.
   - All OT/IT devices may communicate with each other OT/IT device along the same branch.

Additionally, you can specify a `"upper_connection_count"` to limit the number of allowed connections in the network.

### Security
The security part of the configuration file specifies iterations, ruleset anomalies, and a stateful rule percentage.

```
"security": {
   "iterations": X,
   "ruleset_anomaly_count": X,
   "stateful_rule_percentage": X
}
```

As for every generation step, a user can configure GeNESIS to execute the security generation step multiple times with the help of `"iterations"`.
> Note however, that the security step is applied after every communication generation step. Hence, GeNESIS will generate $topology.iterations * communication.iterations * security.iterations$ different evaluation scenarios.

The other two parameters concern the layout of generated rulesets of routers in the network.
- `ruleset_anomaly_count` specifies the number of anomalies in rulesets, i.e., the number of intersecting rules of different actions.
By default, GeNESIS only generates whitelisting rulesets with ACCEPT rules for each allowed connection.
To create optimizable rulesets for optimization algorithms, GeNESIS allows you to configure an anomaly count.
If possible, GeNESIS will create that many anomalies in every ruleset.
- `stateful_rule_percentage` defines the percentage of rules defined with connection state references, e.g., `NEW` or `ESTABLISHED`.
