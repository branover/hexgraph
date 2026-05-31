"""Probe scripts that run INSIDE the sandbox container (baked into the image at
/opt/hexgraph). Importable as a package only so their directory ships with the
wheel and can be dev-mounted; they are executed as standalone scripts."""
