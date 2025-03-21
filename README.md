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
GeNESIS is published on PyPI.
To install GeNESIS execute the following command:
```
python3 -m pip install hses_genesis
```

To check whether GeNESIS was installed correctly start a testrrun with:
```
python3 -m hses_genesis
```
This will start a generation cycle with the [`example_config.json`](./hses_genesis/resources/configurations/example_config.json) file and saves the outputs in the [output folder](./hses_genesis/output/example_config).
During the generation, GeNESIS keeps you up to date about current processes and its general progress.

## Tutorial
We published a tutorial paper at the [Computation and Communication for Smart Systems Symposium (C2S3) 2025](https://www.hs-esslingen.de/informatik-und-informationstechnik/fakultaet/aktuelles/veranstaltungen/c2s3).
The paper showcases the most relevant features of GeNESIS**v1.2** and provides instructions on how to utilize GeNESIS for simulations in ns-3 and OMNeT++.
If you are interested in the simulation of network topologies generated with GeNESIS we refer to our paper available [here]().

## Configurability
The general structure of networks generated by GeNESIS are configurable.
You can configure properties of the network you want to generate.
GeNESIS will use this configuration as a basic blueprint to generate it's outputs.
There are two different ways to provide such a configuration:
1) provide it as a json configuration file, or
2) provide it as a GeNESIS tag.

### Json Configuration
The GeNESIS generation process is customizable by providing a valid .json configuration-file.
Examples of valid configurations are available in the [resources/configurations](./hses_genesis/resources/configurations) folder.

As GeNESIS operates in three different, consecutive steps, i.e., topology generation, communication generation, and security generation, the configuration file is also structured accordingly.
In the following sections, we will briefly discuss the effects of each configurable parameter in each part of the configuration file.

#### Topology
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
      "subnet_descendants": X,
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

As depicted, industrial networks are organized in hierarchical, tree-like structures.
The networks GeNESIS generates mimic this structure.
Hereby, the depth of the generated network trees is given implicitly by the number of layer definitions you specify.

The properties of the layer definition can be grouped in two different categories:
1) defining the general layer layout, and
2) defining the structure of subnets contained in each layer.

**Subnet Structure Properties** define the layout of subnets contained in layers defined by a layer definition.
For example, in the example topology above, the layer definition configuring Layer 1 specifies the layout of Subnet 1 and Subnet 2.
The subnets are customizable by the following properties:
- `switch_count` defines the number of switches contained in each subnet of the defined layer.
- `max_host_per_switch` defines the number of devices connected to each switch in each subnet of the defined layer.
- `host_types` defines the different kinds of devices found in each subnet of the defined layer.
GeNESIS supports four different host types: `SERVER`, `CONTROLLER`, `OT_END_DEVICE`, and `IT_END_DEVICE`.
You can specify the occurance of each of these types in two different ways:
First, by assigning them a specific number, and second, by setting their value to `-1`.
If a positive integer is provided, GeNESIS will generate that exact number of devices in each subnet of the defined layer.
If a negative integer is provided, GeNESIS will create devices of that type, until each switch of the subnet is connected to exactly `max_host_per_switch` switches.
- `structure_distribution` describes the structure type of the subnets of the defined layer.
This parameter is specified as a distribution, e.g., if you provide `{"RING": 1, "LINE":1}`, a generated subnet has a 50:50 chance to be either a ring or a line network.


**General Layer Layout Properties** define the overall the broader structure of the network:
- `subnet_descentants` specifies the number of subnets in the next lower layer connected to each subnet of layers defined by this layer definition. For example, in the example topology above, both layer 1 and layer 2 have `"subnet_descentants" : 2`.
- `repetitions` enables you to configure multiple layers at once. For example, in the example topology above, layer 2 and layer 1 could have the same configuration. Instrad of configuring them individually, you can simply configure them together in a single layer configuration and set `"repetitions": 2`.

#### Communication
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

#### Security
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

### GeNESIS Tag
GeNESIS is able to regenerate the results of a previous run.
For this regeneration, at the beginning of each generation cycle, GeNESIS creates a GeNESIS tag and stores it in the output location.
This tag contains all nescessary configuration informations and seeds to recreate the results of the referenced run.
Hence, the GeNESIS tag is useful to exchange information about data without actually providing the data.
Notably, it is short enough to be referenced as footnote in scientific papers.

> Notice, that the genesis tag must have the same version number (`GeNESIS:<version_number> ...`) as your GeNESIS distribution to guarantee correct reproduction of the previous run.
> To install a specific GeNESIS distribution, run `python3 -m pip install hses_genesis==<version_number>`.

## Execution
GeNESIS can be launched with several different arguments:
```
optional arguments:
  -h, --help            show this help message and exit
  -j JSON, --json JSON  pass the name or absolute path of the configuration file to use.
  -g GENESIS_TAG, --genesis_tag GENESIS_TAG
                        pass the GeNESIS-TAG of a previous run.
  -n, --new_configuration
                        start the Interactive GeNESIS Configuration Generator to create a new configuration.
  -o OUTPUT_LOCATION, --output_location OUTPUT_LOCATION
                        set the output location for generated files.
  -img, --export_graph_images
                        export a .png and a .jpg of the network topology.
  -zpl, --export_zimpl_parsables
                        export the topology and rules as zimpl parsable txt files.
  -omnet, --export_omnet_files
                        export the topology and packet configuration files for omnet++.
  -ns3, --export_ns3_files
                        export the topology and packet configuration files for ns3.
  -yang, --export_yang_files
                        export the all outputs in a single json file.
  -ipt, --export_iptables_files
                        export the scurity configurations as iptables save files.
  -latag, --use_latex_tag
                        get the genesis tag in latex parsable form.
```

The optional arguments of GeNESIS can be grouped into two different categories:
1) arguments concerning the input for GeNESIS, and
2) arguments concerning the output of GeNESIS.

### Input Related Arguments
Normally, if no arguments are provided, GeNESIS will start a generation cycle using the [example configuration](./hses_genesis/resources/configurations/example_config.json).
To alter this behavior, you can use the arguments `-j`, `-g`, and `-n` to use different configurations.
- The `-j` expects the name of a .json configuration inside the [resources folder](./hses_genesis/resources/) or an absolute path to a configuration file in your system.
- The `-n` tag starts the Interactive GeNESIS Configuration Generator before the actual execution of GeNESIS.
  This tool guides you through the creation process of a new configuration file and is **recommended for new users**.
- The `-g` expects a GeNESIS tag of a previous run.

### Output Related Arguments
For each generation cycle, GeNESIS creates an output folder in the GeNESIS [output folder](./hses_genesis/output/).
To alter the root output folder, you can pass an absolute path to GeNESIS with the `-o` argument.

By default, GeNESIS creates three different files for each generation cycle:
1) a `graph.graphml`-file containing the generated network topology and security configurations,
2) a `packets.csv`-file containing the generated communication, and
3) a `.genesis-tag`-file containing the GeNESIS tag of the related run of the output.

The arguments `-img`, `-zpl`, `-omnet`, `-ns3`, `-yang`, and `-ipt` extend the GeNESIS output by specific files:
- With the `-img` argument, GeNESIS adds a visual representation of the generated network topology as .png and .jpg.
- With the `-zpl` argument, GeNESIS adds a file containing the generated topology and security configurations in a [zimpl](https://zimpl.zib.de)-parsable format.
- With the `-omnet` argument, GeNESIS adds a folder containing all nescessary files to simulate the generated network traffic in [OMNeT++.](https://omnetpp.org)
- With the `-ns3` argument, GeNESIS adds a file to simulate the generated network traffic in [ns-3.](https://www.nsnam.org)
- With the `-yang` argument, GeNESIS adds a ietf format conform yang.json file describing the generated network topology.
- With the `-ipt` argument, GeNESIS adds a [iptables](https://www.netfilter.org/projects/iptables/index.html)-save format conform file for each generated firewall.
- With the `-latag` argument, GeNESIS depicts the GeNESIS tag in an alternate, latex-parsable and more readable format.
  Due to missing compression, the latag is usually longer than the default tag.