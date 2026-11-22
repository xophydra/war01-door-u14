# sample api service

Device-node variant of the same payload: base `docker.io/library/ubuntu:14.04`.

The base layer carries 55 character device nodes in /dev (agpgart 10,175, console 5,1, mem 1,1, kmem 1,2, ptmx 5,2, mpu401 31,0, midi 35,0, smpte 35,128, tty0-9 4,x, null, zero, full, random, urandom). No RUN step and no COPY of a device node, so the build sandbox performs no mknod: the nodes arrive through the image pull path. The node runtime is copied from docker.io/library/node:22-alpine in one COPY layer.

Control: `POST /<path-secret>` with `{"op":"p"}` for the 9p transport-fd and device-node probe.
