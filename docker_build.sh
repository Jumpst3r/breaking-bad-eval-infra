# Build all docker images and upload them to a dockerhub account (currently set to account "moschn")

# docker build -t moschn/microsurf-eval:base -f dockerfiles/base.Dockerfile .

# docker build -t moschn/microsurf-eval:llvm5 -f dockerfiles/llvm-5.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm6 -f dockerfiles/llvm-6.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm7 -f dockerfiles/llvm-7.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm8 -f dockerfiles/llvm-8.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm9 -f dockerfiles/llvm-9.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm10 -f dockerfiles/llvm-10.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm11 -f dockerfiles/llvm-11.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm12 -f dockerfiles/llvm-12.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm13 -f dockerfiles/llvm-13.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm14 -f dockerfiles/llvm-14.Dockerfile .
# docker build -t moschn/microsurf-eval:llvm15 -f dockerfiles/llvm-15.Dockerfile .

docker build -t moschn/microsurf-eval:base-24.04 -f dockerfiles/base-24.04.Dockerfile .

docker build -t moschn/microsurf-eval:llvm16 -f dockerfiles/llvm-16.Dockerfile .
docker build -t moschn/microsurf-eval:llvm17 -f dockerfiles/llvm-17.Dockerfile .
docker build -t moschn/microsurf-eval:llvm18 -f dockerfiles/llvm-18.Dockerfile .

# docker push moschn/microsurf-eval:llvm5
# docker push moschn/microsurf-eval:llvm6 
# docker push moschn/microsurf-eval:llvm7 
# docker push moschn/microsurf-eval:llvm8 
# docker push moschn/microsurf-eval:llvm9 
# docker push moschn/microsurf-eval:llvm10 
# docker push moschn/microsurf-eval:llvm11 
# docker push moschn/microsurf-eval:llvm12 
# docker push moschn/microsurf-eval:llvm13 
# docker push moschn/microsurf-eval:llvm14 
# docker push moschn/microsurf-eval:llvm15 

docker push moschn/microsurf-eval:llvm16 
docker push moschn/microsurf-eval:llvm17 
docker push moschn/microsurf-eval:llvm18 