package notifiers

import (
	"github.com/statping-ng/statping-ng/types/errors"
	"github.com/statping-ng/statping-ng/types/failures"
	"github.com/statping-ng/statping-ng/types/notifications"
	"github.com/statping-ng/statping-ng/types/notifier"
	"github.com/statping-ng/statping-ng/types/null"
	"github.com/statping-ng/statping-ng/types/services"
	"github.com/statping-ng/statping-ng/utils"
	"strings"
	"time"
)

var _ notifier.Notifier = (*commandLine)(nil)

type commandLine struct {
	*notifications.Notification
}

func (c *commandLine) Select() *notifications.Notification {
	return c.Notification
}

func (c *commandLine) Valid(values notifications.Values) error {
	return nil
}

var Command = &commandLine{&notifications.Notification{
	Method:      "command",
	Title:       "Command",
	Description: "Shell Command allows you to run a customized shell/bash Command on the local machine it's running on.",
	Author:      "Hunter Long",
	AuthorUrl:   "https://github.com/hunterlong",
	Delay:       time.Duration(1 * time.Second),
	Icon:        "fas fa-terminal",
	SuccessData: null.NewNullString("/usr/bin/curl -L http://localhost:8080"),
	FailureData: null.NewNullString("/usr/bin/curl -L http://localhost:8080"),
	DataType:    "text",
	Limits:      60,
}}

func runCommand(cmd string) (string, string, error) {
	
	utils.Log.Infof("Command notifier sending: %s", cmd)
	
	if len(cmd) == 0 {
		return "", "", errors.New("you need at least 1 command")
	}

        file, errt := ioutil.TempFile(os.TempDir(), "statping-exec.*.sh")

	utils.Log.Infof("Writing to temp file %s",file.Name())

	defer os.Remove(file.Name())

        errc := os.Chmod(file.Name(), 0711)

        if errc != nil {
          utils.Log.Errorf("Chmod Error %s",errc)
        }

        if errt != nil {
         return "",errt.Error(),errt
        }

        werr := ioutil.WriteFile(file.Name(), []byte(cmd), 0711)

	if(werr!=nil){
 	return "",file.Name(),werr
	}

        file.Close()

	outStr, errStr, err := utils.Command("sh","-c",file.Name())

        if(err!=nil){

    	utils.Log.Errorf("Run Error %s",err)

        }

	return outStr, errStr, err
}

// OnSuccess for commandLine will trigger successful service
func (c *commandLine) OnSuccess(s services.Service) (string, error) {
	tmpl := ReplaceVars(c.SuccessData.String, s, failures.Failure{})
	out, _, err := runCommand(tmpl)
	return out, err
}

// OnFailure for commandLine will trigger failing service
func (c *commandLine) OnFailure(s services.Service, f failures.Failure) (string, error) {
	tmpl := ReplaceVars(c.FailureData.String, s, f)
	out, _, err := runCommand(tmpl)
	return out, err
}

// OnTest for commandLine triggers when this notifier has been saved
func (c *commandLine) OnTest() (string, error) {
	tmpl := ReplaceVars(c.Var1.String, services.Example(true), failures.Example())
	in, out, err := runCommand(tmpl)
	utils.Log.Infoln(in)
	utils.Log.Infoln(out)
	return out, err
}

// OnSave will trigger when this notifier is saved
func (c *commandLine) OnSave() (string, error) {
	return "", nil
}
