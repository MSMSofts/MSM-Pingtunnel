package pingtunnel

import (
    "bytes"
    "go/ast"
    "go/format"
    "go/parser"
    "go/token"
    "strings"
    "testing"
)

// This catches the root cause of the post-Multi-Port TCP/UDP regression.
// In 3.4.6 the Foreign core encoded Tcpmode=0 for every TCP DATA response:
// the legacy single-protocol core ignored it, but Multi-Port classified the
// frame as UDP and placed it in the 256-slot UDP queue.
//
// It is a source-level contract because integration round-trip tests using
// small frames passed even when all TCP replies were mislabeled as UDP.
func TestAllForeignTCPDATARepliesCarryActualProtocolMode(t *testing.T) {
    fs:=token.NewFileSet()
    parsed,err:=parser.ParseFile(fs,"server.go",nil,0)
    if err!=nil {t.Fatal(err)}
    const modeIndex=11
    found:=0
    var incorrect []string
    expr:=func(node ast.Node)string {
        var b bytes.Buffer
        if err:=format.Node(&b,fs,node);err!=nil{t.Fatal(err)}
        return strings.TrimSpace(b.String())
    }
    ast.Inspect(parsed,func(node ast.Node)bool{
        call,ok:=node.(*ast.CallExpr)
        if !ok {return true}
        id,ok:=call.Fun.(*ast.Ident)
        if !ok||id.Name!="sendICMP"||len(call.Args)<=modeIndex{return true}
        if !strings.Contains(expr(call.Args[6]),"MyMsg_DATA"){return true}
        found++
        mode:=expr(call.Args[modeIndex])
        if mode!="conn.tcpmode" {
            incorrect=append(incorrect,mode)
        }
        return true
    })
    if found!=4 {
        t.Fatalf("expected all 4 Foreign TCP+UDP DATA send paths; found %d",found)
    }
    if len(incorrect)>0 {
        t.Fatalf("TCP return frames misclassified as UDP on the wire: Tcpmode expressions %v",incorrect)
    }
}
