{
  description = "oauth2-dummy";

  # Specifies the flake inputs
  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Defines how to build the flake for each system
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Import the nixpkgs with overlays and configuration specific to the system
        pkgs = import nixpkgs {
          inherit system;
          overlays = [];
        };
        app = pkgs.buildGoModule {
            name = "oauth2_dummy";
            src =  ./.;

            vendorSha256 = "sha256-FCxOjCfEV37XFqF3crlu4pPC1KsWQOL6U9ygCMGmeTs=";
            # buildFlagsArray = [ "-ldflags=-X main.variable=value" ];
        };
        dockerImage = pkgs.dockerTools.buildImage {
          name = "oauth2-dummy";
          tag = "latest";
          contents = [ app ];
          config = {
            Cmd = [ "${app}/bin/oauth2-app-test" ];
          };
        };

      in {
        # Describe the packages provided by the flake
        packages = {
            oauth2_dummy = app;
            oauth2_dummy_docker = dockerImage;
        };

        defaultPackage = self.packages.oauth2_dummy;
      }
    );
}