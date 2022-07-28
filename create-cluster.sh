exo compute sks create my-test-cluster --service-level starter --nodepool-name my-test-nodepool --nodepool-size 5 --nodepool-security-group sks-security-group --no-metrics-server --nodepool-instance-type large
exo compute sks kubeconfig my-test-cluster kube-admin --group system:masters > $HOME/.kube/config
kubectl create ns argo
kubectl create secret -n argo docker-registry regcred2 --docker-server="https://index.docker.io/v1/" --docker-username=jumpst3r --docker-password=$DOCKERCRED --docker-email=ndutly@gmail.com
kubectl apply -n argo -f https://raw.githubusercontent.com/argoproj/argo-workflows/master/manifests/quick-start-postgres.yaml
kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/master/deploy/longhorn.yaml
kubectl apply -n argo -f k8s-config/pvol-claim.yaml
