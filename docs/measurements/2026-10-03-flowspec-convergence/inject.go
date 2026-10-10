package main

import (
	"context"
	"encoding/json"
	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"net/netip"
	"os"
	"time"
)

func main() {
	conn, err := grpc.NewClient(os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client := api.NewGoBgpServiceClient(conn)
	for i, addr := range []string{"198.51.100.7/32", "2001:db8::7/128"} {
		prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(addr))
		if err != nil {
			panic(err)
		}
		var source bgp.FlowSpecComponentInterface = bgp.NewFlowSpecSourcePrefix(prefix)
		family := bgp.RF_FS_IPv4_UC
		if i == 1 {
			source = bgp.NewFlowSpecSourcePrefix6(prefix, 0)
			family = bgp.RF_FS_IPv6_UC
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if os.Args[2] == "read" {
			stream, err := client.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: apiutil.ToApiFamily(family.Afi(), family.Safi())})
			if err != nil {
				panic(err)
			}
			for {
				r, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					panic(err)
				}
				for _, p := range r.Destination.Paths {
					json.NewEncoder(os.Stdout).Encode(map[string]any{"family": family.String(), "identifier": p.Identifier, "local_identifier": p.LocalIdentifier})
				}
			}
		} else {
			nlri, err := bgp.NewFlowSpecUnicast(family, []bgp.FlowSpecComponentInterface{source})
			if err != nil {
				panic(err)
			}
			mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri, ID: 7}}, netip.IPv4Unspecified())
			if err != nil {
				panic(err)
			}
			path, err := apiutil.NewPath(family, nlri, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(2), bgp.NewPathAttributeCommunities([]uint32{4259912202}), mp, bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewTrafficRateExtended(0, 0)})}, time.Now())
			if err != nil {
				panic(err)
			}
			path.Identifier = 7
			_, err = client.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: path})
			if err != nil {
				panic(err)
			}
		}
		cancel()
	}
}
