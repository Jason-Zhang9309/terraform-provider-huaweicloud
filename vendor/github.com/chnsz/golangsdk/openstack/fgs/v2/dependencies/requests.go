package dependencies

import (
	"github.com/chnsz/golangsdk"
	"github.com/chnsz/golangsdk/pagination"
)

var requestOpts = golangsdk.RequestOpts{
	MoreHeaders: map[string]string{"Content-Type": "application/json", "X-Language": "en-us"},
}

// DependOpts is the structure required by Create and Update method to create a new dependency or update an existing
// dependency.
type DependOpts struct {
	// Import mode. Options: obs and zip.
	Type string `json:"depend_type" required:"true"`
	// Runtime.
	// Enumeration values:
	//   Java8
	//   Node.js6.10
	//   Node.js8.10
	//   Node.js10.16
	//   Node.js12.13
	//   Python2.7
	//   Python3.6
	//   Go1.8
	//   Go1.x
	//   C#(.NET Core 2.0)
	//   C#(.NET Core 2.1)
	//   C#(.NET Core 3.1)
	//   PHP 7.3
	Runtime string `json:"runtime" required:"true"`
	// Name of the dependency. The name can contain a maximum of 96 characters and must start with a letter and end with
	// a letter or digit. Only letters, digits, underscores (_), periods (.), and hyphens (-) are allowed.
	Name string `json:"name,omitempty"`
	// Description of the dependency, which can contain a maximum of 512 characters.
	Description *string `json:"description,omitempty"`
	// When depend_type is set to zip, this parameter is required and indicates the file stream format.
	File string `json:"depend_file,omitempty"`
	// When depend_type is set to obs, this parameter indicates the address of the dependency stored in OBS.
	Link string `json:"depend_link,omitempty"`
}

// Create is a method to create a new custom dependency using a ZIP file in an OBS bucket.
func Create(c *golangsdk.ServiceClient, opts DependOpts) (*Dependency, error) {
	b, err := golangsdk.BuildRequestBody(opts, "")
	if err != nil {
		return nil, err
	}

	var rst golangsdk.Result
	_, err = c.Post(rootURL(c), b, &rst.Body, &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	if err == nil {
		var r Dependency
		rst.ExtractInto(&r)
		return &r, nil
	}
	return nil, err
}

// DependVersionOpts is the structure required by CreateVersion method to create a new dependency (with version info).
type DependVersionOpts struct {
	// Import mode.
	// Valid options are obs and zip.
	Type string `json:"depend_type" required:"true"`
	// Runtime.
	// Enumeration values:
	// + Java8
	// + Java11
	// + Node.js6.10
	// + Node.js8.10
	// + Node.js10.16
	// + Node.js12.13
	// + Node.js14.18
	// + Python2.7
	// + Python3.6
	// + Python3.9
	// + Go1.8
	// + Go1.x
	// + C#(.NET Core 2.0)
	// + C#(.NET Core 2.1)
	// + C#(.NET Core 3.1)
	// + Custom
	// + PHP 7.3
	// + http
	Runtime string `json:"runtime" required:"true"`
	// Name of the dependency. The name can contain a maximum of 96 characters and must start with a letter and end with
	// a letter or digit. Only letters, digits, underscores (_), periods (.), and hyphens (-) are allowed.
	Name string `json:"name" required:"true"`
	// Description of the dependency, which can contain a maximum of 512 characters.
	Description *string `json:"description,omitempty"`
	// When depend_type is set to zip, this parameter is required and indicates the file stream format.
	// Base64 encoded zip file is required.
	// The maximum size of the file to be uploaded is 40MB. If the size exceeds 40MB, upload the file using OBS.
	File string `json:"depend_file,omitempty"`
	// When depend_type is set to obs, this parameter indicates the address of the dependency stored in OBS.
	Link string `json:"depend_link,omitempty"`
}

// CreateVersion is a method to create a new custom dependency (with version info) using a ZIP file in an OBS bucket.
func CreateVersion(c *golangsdk.ServiceClient, opts DependVersionOpts) (*DependencyVersion, error) {
	b, err := golangsdk.BuildRequestBody(opts, "")
	if err != nil {
		return nil, err
	}

	var r DependencyVersion
	_, err = c.Post(rootVersionURL(c), b, &r, &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	return &r, err
}

// Get is a method to obtain a custom dependency detail using its ID.
func Get(c *golangsdk.ServiceClient, dependId string) (*Dependency, error) {
	var r Dependency
	_, err := c.Get(resourceURL(c, dependId), &r, &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	return &r, err
}

// GetVersion is a method to obtain a custom dependency (with version info) detail using its depend ID and specified version.
func GetVersion(c *golangsdk.ServiceClient, dependId, version string) (*DependencyVersion, error) {
	var r DependencyVersion
	_, err := c.Get(resourceVersionURL(c, dependId, version), &r, &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	return &r, err
}

// ListOpts allows to filter list data using given parameters.
type ListOpts struct {
	// Dependency type, which support public, private, and all, default to all.
	//   public
	//   private
	//   all
	DependencyType string `q:"dependency_type"`
	// Runtime of function.
	Runtime string `q:"runtime"`
	// Name of the dependency.
	Name string `q:"name"`
	// Final record queried last time. Default value: 0.
	Marker string `q:"marker"`
	// Maximum number of dependencies that can be obtained in a query, default to 400.
	Limit string `q:"limit"`
}

// ListOptsBuilder is an interface which to support request query build of
// the dependent package search.
type ListOptsBuilder interface {
	ToListQuery() (string, error)
}

// ToListQuery is a method which to build a request query by the ListOpts.
func (opts ListOpts) ToListQuery() (string, error) {
	q, err := golangsdk.BuildQueryString(opts)
	return q.String(), err
}

// List is a method to obtain an array of one or more dependent packages according to the query parameters.
func List(client *golangsdk.ServiceClient, opts ListOptsBuilder) pagination.Pager {
	url := rootURL(client)
	if opts != nil {
		query, err := opts.ToListQuery()
		if err != nil {
			return pagination.Pager{Err: err}
		}
		url += query
	}

	return pagination.NewPager(client, url, func(r pagination.PageResult) pagination.Page {
		p := DependencyPage{pagination.MarkerPageBase{PageResult: r}}
		p.MarkerPageBase.Owner = p
		return p
	})
}

// ListVersionsOpts allows to filter list data of the dependencies (with version info) using given parameters.
type ListVersionsOpts struct {
	DependId string `json:"-" required:"true"`
	// Final record queried last time. Default value: 0.
	Marker string `q:"marker"`
	// Maximum number of dependencies that can be obtained in a query.
	MaxItems string `q:"maxitems"`
}

// ListVersions is a method that used to query list of dependencies (with version info) using given parameters.
func ListVersions(c *golangsdk.ServiceClient, opts ListVersionsOpts) ([]DependencyVersion, error) {
	url := resourceVersionsURL(c, opts.DependId)
	query, err := golangsdk.BuildQueryString(opts)
	if err != nil {
		return nil, err
	}
	url += query.String()

	pager := pagination.NewPager(c, url, func(r pagination.PageResult) pagination.Page {
		p := DependencyVersionPage{pagination.MarkerPageBase{PageResult: r}}
		p.MarkerPageBase.Owner = p
		return p
	})
	pager.Headers = requestOpts.MoreHeaders
	pages, err := pager.AllPages()
	if err != nil {
		return nil, err
	}
	return extractDependencieVersions(pages)
}

// Update is a method to update the current dependency configuration.
func Update(c *golangsdk.ServiceClient, dependId string, opts DependOpts) (*Dependency, error) {
	b, err := golangsdk.BuildRequestBody(opts, "")
	if err != nil {
		return nil, err
	}

	var r Dependency
	_, err = c.Put(resourceURL(c, dependId), b, &r, &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	return &r, err
}

// Delete is a method to remove the current dependency configuration using its ID.
func Delete(c *golangsdk.ServiceClient, dependId string) *golangsdk.ErrResult {
	var r golangsdk.ErrResult
	_, r.Err = c.Delete(resourceURL(c, dependId), &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	return &r
}

// DeleteVersion is a method to remove the specified dependency (with version info) using its depend ID and version.
func DeleteVersion(c *golangsdk.ServiceClient, dependId, version string) error {
	_, err := c.Delete(resourceVersionURL(c, dependId, version), &golangsdk.RequestOpts{
		MoreHeaders: requestOpts.MoreHeaders,
	})
	return err
}
