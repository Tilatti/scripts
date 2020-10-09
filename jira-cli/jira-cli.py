#!/usr/bin/env python3

from jira import JIRA

import tempfile
import os
import subprocess
import re

EDITOR = os.environ.get("EDITOR", "vim")

def read_from_user(fields):
    """Ask the user to edit the input parameter, return the modified one."""
    def call_editor(initial_message):
        with tempfile.NamedTemporaryFile(suffix=".tmp") as f:
            f.write(initial_message.encode("utf-8"))
            f.flush()
            subprocess.run([EDITOR, f.name])
            f.seek(0)
            edited_message = f.read()
        return edited_message.decode("utf-8")
    # Call the editor
    initial_message = ""
    for name, old_value in fields:
        initial_message += "{}: {}\n".format(name, old_value)
    message = call_editor(initial_message)
    # Parse the result of the editting
    current_key = None
    for line in message.split("\n"):
        m = re.search("([A-Za-z]*): (.*)", line)
        if m is not None:
            try:
                fields[m.group(1)] = m.group(2)
            except KeyError:
                if current_key is None:
                    raise Exception()
                fields[current_key] = line
            else:
                current_key = m.group(1)
        else:
            if current_key is None:
                raise Exception()
            fields[current_key] = line
    return fields

def format_html(text):
    """Use w3m utility to format HTML."""
    ret = subprocess.run(["w3m", "-T", "text/html", "-dump"],
        input=text, encoding="utf-8", check=True, capture_output=True)
    return ret.stdout

class Project:
    def __init__(self, jira, key):
        self.key =  key
        self.jira = jira
        self.jira_project = jira.project(key)
        self.last_non_released_version = Version(self, self.jira_project.versions[-1])

    def list_versions(self):
        return [Version(project, jira_version) for jira_version in self.jira_project.versions]

    def list_issues(self, all_issues=False, fix_version=None):
        """Return (by default) all the unclosed issues."""
        fs = ["(project={})".format(self.key)]
        if not all_issues:
            fs += ["(status != resolved)", "(status != closed)"]
        if fix_version is not None:
            fs += ["(fixVersion = \"{}\")".format(fix_version.key)]
        filter_string = " AND ".join(fs)
        return map(lambda jira_issue: Issue(self, jira_issue), jira.search_issues(filter_string, maxResults=None))

import datetime

class Version:
    def __init__(self, project, jira_version):
        self.project = project
        self.key = "{}".format(jira_version)
        self.jira_version = jira_version
        self.jira = project.jira
    def list_issues(self):
        return self.project.list_issues(all_issues=True, fix_version=self)
    def compute_dates(self):
        ts_created_min = datetime.datetime.now().timestamp()
        ts_resolution_max = 0 # 1 Janv 1970
        for issue in self.list_issues():
            # Get the date the issue was resolved
            resolution = issue.jira_issue.fields.resolutiondate
            if resolution is not None:
                iso_resolution = resolution.split("+")[0]
                ts_resolution = datetime.datetime.fromisoformat(iso_resolution).timestamp()
            else:
                ts_resoltuion = datetime.datetime.now().timestamp()
            # Get the date the issue was created
            iso_created = issue.jira_issue.fields.created.split("+")[0]
            ts_created = datetime.datetime.fromisoformat(iso_created).timestamp()
            # Compute the minimal & maximal values
            if ts_created < ts_created_min:
                ts_created_min = ts_created
            if ts_resolution > ts_resolution_max:
                ts_resolution_max = ts_resolution
        return (datetime.datetime.fromtimestamp(ts_created_min), datetime.datetime.fromtimestamp(ts_resolution_max))

class Commit:
    def __init__(self, author, revision, files=[], date=None):
        self.author = author
        self.revision = revision
        self.files = files
        self.date = date

    class DescriptionIsCorrupted(Exception):
        pass

    @staticmethod
    def from_description(body):
        """Parse a commit description (taken from a ticket's comment) to returns an instance of Commit()."""
        author = None
        revision = None
        root = None
        in_change_list = False
        files = []
        for line in body.split("\n"):
            if not in_change_list:
                m = re.search("Author[^:]*: (.*)", line)
                if m is not None:
                    author = m.group(1)
                m = re.search("Revision[^:]*: (.*)", line)
                if m is not None:
                    revision = m.group(1)
                m = re.search("^https://([^/]*)[^?]*\?root=([^&]*)&.*$", line)
                if m is not None:
                    root = "https://{}/svn/{}/".format(m.group(1), m.group(2))
                if line == "Changed:":
                    in_change_list = True
            else:
                m = re.search(". *([^\ ]*)", line)
                if m is not None:
                    files.append(m.group(1)) 
                else:
                    in_change_list = False
        if (revision is None) or (author is None) or (root is None):
            raise Commit.DescriptionIsCorrupted("The revision or author are not found in the commit comments.")
        files = map((lambda f: "{}/{}".format(root, f)), files)
        return Commit(author, revision, files)

    def __str__(self):
        return "{} commited the revision {}.".format(self.author, self.revision)

class Issue:
    def __init__(self, project, jira_issue):
        self.project = project
        self.jira = project.jira
        self.jira_issue = jira_issue

    class TransitionFailed(Exception):
        pass

    @staticmethod
    def from_key(project, key):
        jira_issue = jira.issue("{}-{}".format(project.key, key))
        if jira_issue is None:
            raise Exception("Selected issue key {} doesn't exist.".format(args.ticket))
        return Issue(project, jira_issue)

    @staticmethod
    def create_issue(project, summary, description):
        jira_issue = self.jira.create_issue(project=self.project.key,
            summary=summary, description=description, issuetype={"name": "Change"})
        return Issue(project, jira_issue)

    @staticmethod
    def create_issue_from_user(project):
        summary, description = read_from_user([("SUMMARY", ""), ("DESCRIPTION", "")])
        return Issue.create_issue(project, summary, description)

    def update_issue_from_user(self):
        summary, description = read_from_user \
            ([("SUMMARY", self.jira_issue.fields.summary), ("DESCRIPTION", self.jira_issue.fields.description)])
        self.jira_issue.update(summary=summary, description=description)

    def transit_to(self, name):
        transition_id = self.jira.find_transitionid_by_name(self.jira_issue, name)
        if transition_id is None:
            raise Issue.TransitionFailed()
        self.jira.transition_issue(self.jira_issue, transition_id)

    def begin_to_work(self, fix_version):
        """Begin to work on a newly created self.jira_issue."""
        self.jira.assign_issue(issue, user)
        for name in ["Acknowledge Issue", "Confirm Issue", "Assign Issue", "Start working"]:
            try:
                transit_to(self.jira, self.jira_issue, name)
            except Issue.TransitionFailed:
                print_warning("Unable to transit on '{}' (already transited ?).".format(name))
            else:
                print("Transited to '{}'.".format(name))
        self.jira_issue.add_field_value("fixVersions", {"id": fix_version.id})
        print("Current issue status is '{}'.".format(self.jira_issue.fields.status))
        print("The issue will be fixed on the version '{}'.".format(fix_version))

    def finished_to_work(self):
        """Finish to work on the issue. Pass to 'ready for review'."""
        self.jira.assign_issue(self.jira_issue, user)
        try:
            transit_to(self.jira, self.jira_issue, "Ready for review")
        except Issue.TransitionFailed:
            print_warning("Unable to transit on '{}' (already transited ?).".format(name))
        else:
            print("Transited to '{}'.".format(name))
        self.jira.assign_issue(self.jira_issue, None) # Unassigned
        print("Current issue status is '{}'.".format(self.jira_issue.fields.status))

import rich
from rich import console
from rich import panel
from rich import table
from rich import columns
from rich import markdown
from rich import padding

console = console.Console()

class CommitDisplayer:
    def __init__(self, commit):
        self.commit = commit
    def __rich_console__(self, console, options):
        yield "[cyan]Author[/cyan] {}".format(self.commit.author)
        if self.commit.date is not None:
            yield "[cyan]Date[/cyan] {}".format(self.commit.date)
        yield "[cyan]Revision[/cyan] {}".format(self.commit.revision)
        md = "".join(["* {}\n".format(f) for f in self.commit.files])
        yield panel.Panel(markdown.Markdown(md))

class IssueDisplayer:
    def __init__(self, issue):
        self.issue = issue
    def __rich_console__(self, console, options):
        yield panel.Panel("[red]{}[/red] - {}"
            .format(self.issue.jira_issue.key, self.issue.jira_issue.fields.summary), border_style="yellow")
        yield "[cyan]Assignee[/cyan] {}".format(self.issue.jira_issue.fields.assignee)
        yield "[cyan]Reporter[/cyan] {}".format(self.issue.jira_issue.fields.reporter)
        yield "[cyan]Status[/cyan] {}".format(self.issue.jira_issue.fields.status)
        yield "[cyan]Created[/cyan] {} / [cyan]Updated[/cyan] {}" \
            .format(self.issue.jira_issue.fields.created, self.issue.jira_issue.fields.updated)
        yield "[cyan]Fix version[/cyan] {}" \
            .format(", ".join([v.name for v in self.issue.jira_issue.fields.fixVersions]))
        yield panel.Panel(format_html(self.issue.jira_issue.fields.description))
        if self.issue.jira_issue.fields.comment.comments:
            yield panel.Panel("Comments", border_style="yellow")
        for comment in self.issue.jira_issue.fields.comment.comments:
            if "SCM" in comment.author.name:
                try:
                    commit = Commit.from_description(comment.body)
                except Commit.DescriptionIsCorrupted as e:
                    yield "[cyan]Author[/cyan] {}".format(comment.author)
                    yield "[cyan]Created[/cyan] {}".format(comment.created)
                    yield panel.Panel(format_html(comment.body))
                else:
                    commit.date = comment.created
                    yield from CommitDisplayer(commit).__rich_console__(console, options)
            else:
                yield "[cyan]Author[/cyan] {}".format(comment.author)
                yield "[cyan]Created[/cyan] {}".format(comment.created)
                yield panel.Panel(format_html(comment.body))

class IssuesListDisplayer:
    def __init__(self, issues, title="List of issues"):
        self.issues = issues
        self.title = title
    def __rich_console__(self, console, options):
        t = table.Table(title=self.title)
        t.add_column("Key")
        t.add_column("Description")
        t.add_column("State")
        t.add_column("Assignee")
        for issue in self.issues:
            t.add_row(issue.jira_issue.key, issue.jira_issue.fields.summary,
                "{}".format(issue.jira_issue.fields.status), "{}".format(issue.jira_issue.fields.assignee))
        yield t

class ProjetDisplayer:
    def __init__(self, project):
        self.project = project
    def __rich_console__(self, console, options):
        t = table.Table(title="[red]{}[/red]".format(self.project.key))
        t.add_column("Version")
        t.add_column("Number of fixed issues")
        t.add_column("Begin to work")
        t.add_column("Finished to work")
        for version in self.project.list_versions():
            (begin_to_work, finished_to_work) = version.compute_dates()
            nb_issues = "{}".format(len(list(version.list_issues())))
            t.add_row("{}".format(version.key), nb_issues, begin_to_work.isoformat(), finished_to_work.isoformat())
        yield t

if __name__ == "__main__":
    import argparse
    import getpass
    import keyring

    # parse the arguments
    parser = argparse.ArgumentParser(prog="jira-cli")
    parser.add_argument('url', metavar='url', type=str, help='URL of the Jira REST API')
    parser.add_argument('project', metavar='project', type=str, help='JIRA key of the project')
    parser.add_argument('--username', dest='username', nargs="?", type=str, help='Username', default=None)
    parser.add_argument('--password', dest='password', nargs="?", type=str, help='Password', default=None)

    subparsers = parser.add_subparsers(dest="action")

    # parse the list action arguments 
    parser_list = subparsers.add_parser("list", help="list the tickets")
    parser_list.add_argument("--last", dest="last", action="store_true",
        help="Only ticket to fix on the next release.")
    parser_list.add_argument("--all", dest="all", action="store_true", help="All the issues")
    parser_list.add_argument("--subject", dest="subject", type=str, help="The subject", default=None)

    # parse the show action arguments 
    parser_edit = subparsers.add_parser("show", help="Show general information about the project")
    # parse the display action arguments 
    parser_display = subparsers.add_parser("display", help="display a ticket")
    parser_display.add_argument("ticket", metavar="ticket", type=str, help="The ticket to display")
    # parse the new action arguments 
    parser_new = subparsers.add_parser("new", help="add a new ticket")
    parser_new.add_argument("--subject", dest="subject", type=str, help="Subject of the new ticket")
    parser_new.add_argument("--summary", dest="summary", type=str, help="Summary of the new ticket")
    parser_new.add_argument("--description", dest="description", type=str, help="Description of the new ticket")
    # parse the edit action arguments 
    parser_edit = subparsers.add_parser("edit", help="edit a ticket")
    parser_edit.add_argument("ticket", metavar="ticket", type=str, help="The ticket to display")
    # parse the begin action arguments 
    parser_edit = subparsers.add_parser("begin", help="begin to work on a ticket")
    parser_edit.add_argument("ticket", metavar="ticket", type=str, help="The ticket to work")
    # parse the end action arguments 
    parser_edit = subparsers.add_parser("end", help="finish to work on a ticket")
    parser_edit.add_argument("ticket", metavar="ticket", type=str, help="The ticket to finish")

    args = parser.parse_args()

    # Try to get the authentication information
    if args.username is not None:
        username = args.username
    else:
        username = getpass.getuser()
    if args.password is not None:
        password = args.password
    else:
        password = keyring.get_password("JIRA-CLI", username)
        if password is None:
            password = getpass.getpass()
    user_authentication = (username, password)
    # Connect to the JIRA server
    jira = JIRA(args.url, auth=(username, password))
    del password

    # Get the reference of the project
    project = Project(jira, args.project)
    if project is None:
        parser.error("The project key seems to be incorrect ...")
    # Get the reference of the issue
    if hasattr(args, "ticket"):
        issue = Issue.from_key(project, args.ticket)
    else:
        issue = None

    if args.action == "list":
        if args.last:
            fix_version = project.last_non_released_version
        else:
            fix_version = None
        issues = project.list_issues(fix_version=fix_version, all_issues=args.all)
        console.print(IssuesListDisplayer(issues))
    elif args.action == "show":
        console.print(ProjetDisplayer(project))
    elif args.action == "new":
        subject = args.subject
        summary = args.summary
        description = args.description
        summary, description = read_from_user(summary, description)
        add_issue(jira, summary, description)
    elif args.action == "edit":
        issue.update_issue_from_user()
    elif args.action == "display":
        console.print(IssueDisplayer(issue))
    elif args.action == "begin":
        issue.begin_to_work(project.last_non_released_version)
    elif args.action == "end":
        issue.finished_to_work()
    else:
        parser.print_help()
