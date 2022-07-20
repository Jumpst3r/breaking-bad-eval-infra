# microsurf-eval-infra

Evaluation scripts for the microsurf repo

## Files

`config.json`: Contains information on how to build the different frameworks for different architectures

`builder.py`: Script used to build and analyze a selected framework

`k8s-config`: Kubernetes config stuff

`create-cluster.sh`: Deploy a large scale cluster on Exoscale and run the evaluation workflow

`workflow/`: Kubernetes workflow engine (argo) templates

`framework-builder/`: driver source code for the different frameworks

`bootstrap-static/`: static result summary (not updated, data from an old run - ignore)
